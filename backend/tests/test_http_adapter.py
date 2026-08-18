"""HTTP probe tests run against a throwaway server bound to loopback.

No test in this suite contacts a system outside the machine running it.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.discovery.base import AdapterRequest, AssetType, Confidence
from app.discovery.http_probe import HTTP_PROBE, HttpProbeAdapter
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


def request(target: str) -> AdapterRequest:
    return AdapterRequest(target=normalize_target(target), profile=HTTP_PROBE)


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
