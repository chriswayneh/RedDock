from app.response_security import SECURITY_HEADERS


def test_api_responses_are_not_cacheable_and_have_browser_security_headers(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_application_response_has_security_headers_without_disabling_asset_caching(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers.get("cache-control") != "no-store"
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_rejected_host_response_keeps_the_security_policy(client):
    response = client.get("/api/health", headers={"Host": "attacker.invalid"})

    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
