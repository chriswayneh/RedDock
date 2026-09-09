from datetime import UTC, datetime

from sqlalchemy import event

from app.config import get_settings
from app.models import Dockyard, Finding, Organization
from tests.phase1 import Recorder


def seed(session, dockyard_id, count):
    recorder = Recorder(session, dockyard_id)
    now = datetime(2026, 9, 1, tzinfo=UTC)
    for index in range(count):
        asset = recorder.asset(f"http://127.0.0.1:{10000 + index}")
        recorder.discovery_run()
        session.add(
            Finding(
                dockyard_id=dockyard_id,
                fingerprint=f"{index:064x}",
                detector="http-policy",
                detector_version="1.0.0",
                rule_id="plaintext-http",
                title="Plaintext HTTP",
                description="Recorded test observation",
                category="configuration",
                severity="medium",
                confidence="observed",
                status="open" if index % 2 == 0 else "accepted",
                asset_id=asset.id,
                first_seen=now,
                last_seen=now,
            )
        )
    session.commit()


def test_dashboard_empty(client):
    assert client.get("/api/dashboard").json() == {
        "dockyard_count": 0,
        "asset_count": 0,
        "discovery_run_count": 0,
        "open_finding_count": 0,
        "recent_dockyards": [],
        "recent_runs": [],
    }


def test_summary_counts_all_rows_but_bounds_recent_lists(client, session, dockyard_id):
    seed(session, dockyard_id, 105)
    for index in range(7):
        client.post("/api/dockyards", json={"name": f"Empty {index}"})
    hidden_org = Organization(slug="private-test", name="Private test")
    session.add(hidden_org)
    session.flush()
    hidden = Dockyard(organization_id=hidden_org.id, name="Not visible")
    session.add(hidden)
    session.flush()
    hidden_id = hidden.id
    seed(session, hidden_id, 2)
    queries = []

    def record(_conn, _cursor, statement, _parameters, _context, _many):
        queries.append(statement)

    event.listen(session.bind, "before_cursor_execute", record)
    try:
        response = client.get("/api/dashboard")
    finally:
        event.remove(session.bind, "before_cursor_execute", record)
    assert response.status_code == 200
    summary = response.json()
    assert summary["dockyard_count"] == 8
    assert summary["asset_count"] == summary["discovery_run_count"] == 105
    assert summary["open_finding_count"] == 53
    assert len(summary["recent_dockyards"]) == 5
    assert len(summary["recent_runs"]) == 8
    assert all(row["id"] != hidden_id for row in summary["recent_dockyards"])
    assert all(row["dockyard_id"] == dockyard_id for row in summary["recent_runs"])
    # Six aggregate/recent queries, plus the fixed local identity lookup.
    assert len(queries) <= 10
    for name in ("assets", "discoveries", "findings", "evidence"):
        response = client.get(f"/api/dockyards/{dockyard_id}/{name}")
        assert response.status_code == 200
        assert len(response.json()) == 100
        assert response.headers["X-Total-Count"] == "105"
        limited = client.get(f"/api/dockyards/{dockyard_id}/{name}?limit=2")
        assert len(limited.json()) == 2
        assert limited.headers["X-Total-Count"] == "105"
        assert client.get(f"/api/dockyards/{hidden_id}/{name}").status_code == 404
    first = client.get(f"/api/dockyards/{dockyard_id}/findings?status=open&limit=50")
    last = client.get(f"/api/dockyards/{dockyard_id}/findings?status=open&offset=50")
    assert first.headers["X-Total-Count"] == last.headers["X-Total-Count"] == "53"
    assert len(first.json()) == 50 and len(last.json()) == 3
    assert not {row["id"] for row in first.json()} & {row["id"] for row in last.json()}
    missing = client.get(f"/api/dockyards/{dockyard_id}/findings?severity=critical")
    assert missing.json() == [] and missing.headers["X-Total-Count"] == "0"


def test_settings_has_only_public_facts(client, monkeypatch):
    monkeypatch.setenv("REDDOCK_LLM_BASE_URL", "https://models.example.test/v1")
    monkeypatch.setenv("REDDOCK_LLM_MODEL", "local-model")
    monkeypatch.setenv("REDDOCK_LLM_API_KEY", "test-key-must-not-appear")
    get_settings.cache_clear()
    result = client.get("/api/settings")
    assert result.status_code == 200
    assert result.json() == {
        "name": "RedDock",
        "version": get_settings().version,
        "phase": get_settings().phase,
        "deployment_mode": "local",
        "intelligence_configured": True,
    }
    assert "test-key" not in result.text and "11434" not in result.text


def test_list_count_is_documented_without_changing_array_body(client):
    from app.main import app

    schema = app.openapi()
    for name in ("assets", "discoveries", "findings", "evidence"):
        response = schema["paths"][f"/api/dockyards/{{dockyard_id}}/{name}"]["get"]["responses"][
            "200"
        ]
        assert "X-Total-Count" in response["headers"]
        assert response["content"]["application/json"]["schema"]["type"] == "array"
