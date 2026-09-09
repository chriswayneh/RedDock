import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.response_security import APPLICATION_CSP


@pytest.mark.parametrize("flag", [None, "false", "invalid", "true"])
def test_docs_require_explicit_enablement(environment, monkeypatch, flag):
    from app.main import create_app

    if flag is not None:
        monkeypatch.setenv("REDDOCK_API_DOCS_ENABLED", flag)
    get_settings.cache_clear()
    with TestClient(create_app(), base_url="http://localhost") as client:
        for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            response = client.get(path)
            assert response.status_code == (200 if flag == "true" else 404)
            if flag == "true":
                assert response.headers["content-security-policy"] != APPLICATION_CSP
            else:
                assert response.headers["content-security-policy"] == APPLICATION_CSP
            rejected = client.get(path, headers={"Host": "attacker.invalid"})
            assert rejected.status_code == 400
            assert rejected.headers["content-security-policy"] == APPLICATION_CSP
        assert client.get("/api/health").status_code == 200


def test_built_spa_deep_links_do_not_shadow_api_or_bundle(environment, monkeypatch, tmp_path):
    import app.main

    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<html>RedDock test bundle</html>", encoding="utf-8")
    (static / "assets" / "main.js").write_text("// test bundle", encoding="utf-8")
    monkeypatch.setattr(app.main, "STATIC_DIRECTORY", static)
    with TestClient(app.main.create_app(), base_url="http://localhost") as client:
        for path in (
            "/",
            "/assets",
            "/assets/",
            "/dockyards/1/findings/2",
            "/settings",
            "/unknown",
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert "RedDock test bundle" in response.text
            assert response.headers["content-security-policy"] == APPLICATION_CSP
        assert client.get("/assets/main.js").text == "// test bundle"
        assert client.get("/assets/missing.js").status_code == 404
        assert client.get("/api/missing").status_code == 404
        assert client.get("/api/health").json()["status"] == "healthy"
        assert client.get("/openapi.json").status_code == 404
