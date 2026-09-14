import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.local_security import (
    OPERATOR_COOKIE_NAME,
    OPERATOR_CSRF_HEADER_NAME,
    OPERATOR_HEADER_NAME,
    LocalMutationDenied,
    LocalMutationThrottled,
    LocalOperatorUnavailable,
    load_or_create_local_operator,
)


def _request(
    *,
    origin: str | None = None,
    token: str | None = None,
    cookie: str | None = None,
    csrf: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if origin is not None:
        headers.append((b"origin", origin.encode("ascii")))
    if token is not None:
        headers.append((OPERATOR_HEADER_NAME.lower().encode("ascii"), token.encode("ascii")))
    if cookie is not None:
        headers.append((b"cookie", f"{OPERATOR_COOKIE_NAME}={cookie}".encode("ascii")))
    if csrf is not None:
        headers.append((OPERATOR_CSRF_HEADER_NAME.lower().encode("ascii"), csrf.encode("ascii")))
    return Request({"type": "http", "method": "POST", "path": "/api/test", "headers": headers})


def test_token_is_created_once_and_only_its_digest_remains_in_runtime(tmp_path: Path):
    path = tmp_path / "operator-token"
    first = load_or_create_local_operator(path)

    assert first.created_token is not None
    assert len(first.created_token) == 43
    assert path.read_text().strip() == first.created_token
    assert first.runtime.verify(first.created_token)
    assert not first.runtime.verify("A" * 43)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600

    second = load_or_create_local_operator(path)
    assert second.created_token is None
    assert second.runtime.verify(first.created_token)


def test_deleted_token_is_not_silently_regenerated(tmp_path: Path):
    path = tmp_path / "operator-token"
    startup = load_or_create_local_operator(path)
    assert startup.created_token is not None
    path.unlink()

    with pytest.raises(LocalOperatorUnavailable):
        startup.runtime.authorize_mutation(_request(token=startup.created_token))

    unavailable = load_or_create_local_operator(path)
    assert unavailable.created_token is None
    assert not unavailable.runtime.available
    with pytest.raises(LocalOperatorUnavailable):
        unavailable.runtime.authorize_mutation(_request(token=startup.created_token))


def test_symlink_token_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    source.write_text("A" * 43)
    path = tmp_path / "operator-token"
    try:
        path.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable")

    with pytest.raises(LocalOperatorUnavailable, match="non-symlink"):
        load_or_create_local_operator(path)


def test_browser_origin_and_single_credential_are_required(tmp_path: Path):
    startup = load_or_create_local_operator(tmp_path / "operator-token")
    token = startup.created_token
    assert token is not None

    startup.runtime.authorize_mutation(_request(token=token))
    browser = startup.runtime.authorize_unlock(
        _request(origin="http://localhost:8080"), token
    )
    startup.runtime.authorize_mutation(
        _request(
            origin="http://localhost:8080",
            cookie=browser.token,
            csrf=browser.csrf_token,
        )
    )
    with pytest.raises(LocalMutationDenied):
        startup.runtime.authorize_mutation(
            _request(origin="http://attacker.example", token=token)
        )
    with pytest.raises(LocalMutationDenied):
        startup.runtime.authorize_mutation(_request(token=token, cookie=browser.token))


def test_browser_session_cannot_be_replayed_as_cookie_or_cli_token(tmp_path: Path):
    startup = load_or_create_local_operator(tmp_path / "operator-token")
    token = startup.created_token
    assert token is not None
    browser = startup.runtime.authorize_unlock(
        _request(origin="http://127.0.0.1:8080"), token
    )

    with pytest.raises(LocalMutationDenied):
        startup.runtime.authorize_mutation(_request(token=browser.token))
    with pytest.raises(LocalMutationDenied):
        startup.runtime.authorize_mutation(
            _request(origin="http://127.0.0.1:8080", cookie=browser.token)
        )
    with pytest.raises(LocalMutationDenied):
        startup.runtime.authorize_mutation(
            _request(
                origin="http://127.0.0.1:8080",
                cookie=browser.token,
                csrf="X" * 43,
            )
        )


def test_browser_sessions_are_bounded_and_expire(monkeypatch, tmp_path: Path):
    import app.local_security as local_security

    moment = 100.0
    monkeypatch.setattr(local_security.time, "monotonic", lambda: moment)
    startup = load_or_create_local_operator(tmp_path / "operator-token")
    token = startup.created_token
    assert token is not None
    sessions = [
        startup.runtime.authorize_unlock(
            _request(origin="http://localhost:8080"), token
        )
        for _ in range(9)
    ]

    assert not startup.runtime.request_is_unlocked(_request(cookie=sessions[0].token))
    assert startup.runtime.request_is_unlocked(_request(cookie=sessions[-1].token))
    moment += 30 * 60
    assert not startup.runtime.request_is_unlocked(_request(cookie=sessions[-1].token))


def test_global_local_mutation_throttle_is_fixed_and_in_process(tmp_path: Path):
    startup = load_or_create_local_operator(tmp_path / "operator-token")
    token = startup.created_token
    assert token is not None

    for _ in range(120):
        startup.runtime.authorize_mutation(_request(token=token))
    with pytest.raises(LocalMutationThrottled):
        startup.runtime.authorize_mutation(_request(token=token))


def test_unlock_endpoint_exchanges_master_token_for_bounded_browser_session(environment: Path):
    import app.main

    with TestClient(app.main.create_app(), base_url="http://localhost") as client:
        token = (environment / "operator-token").read_text().strip()
        locked = client.get("/api/operator/status")
        rejected = client.post("/api/dockyards", json={"name": "Denied"})
        wrong_origin = client.post(
            "/api/operator/unlock",
            headers={"Origin": "http://attacker.example"},
            json={"token": token},
        )
        unlocked = client.post(
            "/api/operator/unlock",
            headers={"Origin": "http://127.0.0.1:8080"},
            json={"token": token},
        )
        status = client.get("/api/operator/status")
        created = client.post(
            "/api/dockyards",
            headers={
                "Origin": "http://127.0.0.1:8080",
                OPERATOR_CSRF_HEADER_NAME: unlocked.json()["csrf_token"],
            },
            json={"name": "Authorized"},
        )

    assert locked.json() == {
        "available": True,
        "unlocked": False,
        "session_id": None,
    }
    assert rejected.status_code == 401
    assert wrong_origin.status_code == 401
    assert token not in wrong_origin.text
    assert unlocked.status_code == 200
    csrf_token = unlocked.json()["csrf_token"]
    session_id = unlocked.json()["session_id"]
    assert len(csrf_token) == 43
    assert len(session_id) == 43
    assert session_id != csrf_token
    cookie = unlocked.headers["set-cookie"]
    assert f"{OPERATOR_COOKIE_NAME}=" in cookie
    assert token not in cookie
    assert token not in unlocked.text
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Domain=" not in cookie
    assert "Max-Age=28800" in cookie
    assert status.json() == {
        "available": True,
        "unlocked": True,
        "session_id": session_id,
    }
    assert created.status_code == 201
