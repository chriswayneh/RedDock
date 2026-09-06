"""HTTP probe tests run against a throwaway server bound to loopback.

No test in this suite contacts a system outside the machine running it.
"""

import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.discovery.base import AdapterRequest, AssetType, Confidence
from app.discovery.http_probe import HTTP_PROBE, PROJECT_URL, HttpProbeAdapter
from app.targets import normalize_target


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "RedDockTest/1.0"

    def do_HEAD(self) -> None:  # method name is fixed by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0")
        self.send_header("Set-Cookie", "session=must-not-be-recorded")
        self.end_headers()

    def log_message(self, *_args) -> None:
        return


class SecureHandler(Handler):
    """A handler that sends the response-level protections a detector looks for."""

    def do_HEAD(self) -> None:  # method name is fixed by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "session=must-not-be-recorded")
        self.end_headers()


@pytest.fixture()
def origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def secure_origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SecureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def request(target: str) -> AdapterRequest:
    return AdapterRequest(target=normalize_target(target), profile=HTTP_PROBE)


def test_http_probe_tls_policy_has_an_explicit_modern_minimum():
    from app.discovery.http_probe import _tls_context

    context = _tls_context()

    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_a_scoped_origin_becomes_a_web_asset_with_one_service(origin: str):
    result = HttpProbeAdapter().run(request(origin))

    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.asset_type is AssetType.WEB
    assert asset.identity == origin
    assert asset.ip_address == "127.0.0.1"
    assert [(service.transport, service.state) for service in asset.services] == [("tcp", "open")]


def test_the_response_and_selected_headers_are_recorded(origin: str):
    result = HttpProbeAdapter().run(request(origin))
    types = {observation.observation_type for observation in result.observations}
    assert "http_response" in types

    headers = {
        observation.detail["header"]: observation.detail["value"]
        for observation in result.observations
        if observation.observation_type == "http_header"
    }
    assert headers["server"] == "RedDockTest/1.0"
    # Session material is deliberately never retained.
    assert "set-cookie" not in headers


def test_a_self_reported_header_is_marked_reported_not_observed(origin: str):
    result = HttpProbeAdapter().run(request(origin))
    by_type = {
        observation.observation_type: observation.confidence
        for observation in result.observations
    }
    assert by_type["http_response"] is Confidence.OBSERVED
    assert by_type["http_header"] is Confidence.REPORTED


def test_the_transcript_is_retained_as_evidence(origin: str):
    result = HttpProbeAdapter().run(request(origin))
    assert [artifact.name for artifact in result.artifacts] == ["http-probe.json"]
    assert b'"status": 200' in result.artifacts[0].content


def test_a_closed_port_is_an_observation_not_a_failure():
    # Port 1 on loopback is not served by the test suite.
    result = HttpProbeAdapter().run(request("http://127.0.0.1:1"))
    assert result.assets == ()
    assert result.observations[0].observation_type == "endpoint_unreachable"


def test_the_adapter_only_accepts_url_targets():
    adapter = HttpProbeAdapter()
    assert adapter.supports(normalize_target("http://127.0.0.1:8080"))
    assert not adapter.supports(normalize_target("127.0.0.1"))
    assert not adapter.supports(normalize_target("192.168.1.0/24"))


def test_the_response_states_which_headers_were_examined(origin: str):
    """A later reader must be able to tell an absent header from an unexamined one."""
    result = HttpProbeAdapter().run(request(origin))
    response = next(
        observation
        for observation in result.observations
        if observation.observation_type == "http_response"
    )

    examined = response.detail["headers_examined"]
    assert {
        "strict-transport-security",
        "x-content-type-options",
        "content-security-policy",
        "x-frame-options",
    } <= set(examined)
    assert response.detail["scheme"] == "http"
    assert response.detail["headers_present"] == sorted(
        observation.detail["header"]
        for observation in result.observations
        if observation.observation_type == "http_header"
    )


def test_security_headers_are_retained_when_the_endpoint_sends_them(secure_origin: str):
    result = HttpProbeAdapter().run(request(secure_origin))
    headers = {
        observation.detail["header"]: observation.detail["value"]
        for observation in result.observations
        if observation.observation_type == "http_header"
    }

    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == "default-src 'self'"
    assert headers["x-frame-options"] == "DENY"
    assert "set-cookie" not in headers


def test_the_user_agent_reports_the_version_the_application_reports():
    """A hard-coded version would drift the moment RedDock is released again."""
    from app.config import get_settings
    from app.discovery.http_probe import user_agent

    assert user_agent() == f"RedDock/{get_settings().version} (+{PROJECT_URL})"
