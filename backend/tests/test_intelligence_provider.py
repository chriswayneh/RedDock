"""The model-provider transport is bounded and does not follow redirects."""

import io
import json
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from app.intelligence.providers import (
    MAX_PROVIDER_RESPONSE_READS,
    OpenAICompatibleProvider,
    ProviderError,
    _DeadlineReader,
)


class ProviderHandler(BaseHTTPRequestHandler):
    mode = "ok"
    authorization: str | None = None
    request: dict | None = None

    def do_POST(self):  # noqa: N802
        type(self).authorization = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", "0"))
        type(self).request = json.loads(self.rfile.read(length))
        if type(self).mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        content = json.dumps({"summary": "Stored evidence only."})
        body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        if type(self).mode == "trickle_headers":
            headers = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
            )
            for byte in headers:
                try:
                    self.connection.sendall(bytes([byte]))
                except OSError:
                    break
                time.sleep(0.02)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if type(self).mode == "many_chunks":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                self.connection.sendall(b"1\r\nx\r\n" * (MAX_PROVIDER_RESPONSE_READS + 1))
            except OSError:
                pass
            return
        if type(self).mode == "trickle_chunk_size":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for byte in f"{len(body):X}\r\n".encode():
                try:
                    self.connection.sendall(bytes([byte]))
                except OSError:
                    break
                time.sleep(0.04)
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if type(self).mode == "trickle":
            for byte in body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except BrokenPipeError:
                    break
                time.sleep(0.02)
        else:
            self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002, ANN001
        return


@contextmanager
def provider_server(mode: str):
    ProviderHandler.mode = mode
    ProviderHandler.authorization = None
    ProviderHandler.request = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_provider_posts_bounded_json_with_configured_authorization():
    with provider_server("ok") as port:
        provider = OpenAICompatibleProvider(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="test-model",
            api_key="test-key",
            sends_data_external=False,
        )
        result = provider.analyze({"findings": []})

    assert result == {"summary": "Stored evidence only."}
    assert ProviderHandler.authorization == "Bearer test-key"
    assert ProviderHandler.request is not None
    assert ProviderHandler.request["model"] == "test-model"
    assert ProviderHandler.request["messages"][1]["content"] == '{"findings": []}'


def test_provider_refuses_redirects():
    with provider_server("redirect") as port:
        provider = OpenAICompatibleProvider(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="test-model",
            sends_data_external=False,
        )
        with pytest.raises(ProviderError, match="rejected"):
            provider.analyze({"findings": []})


def test_provider_enforces_total_deadline_against_trickle_response():
    with provider_server("trickle") as port:
        provider = OpenAICompatibleProvider(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="test-model",
            timeout_seconds=0.1,
            sends_data_external=False,
        )
        started = time.monotonic()
        with pytest.raises(ProviderError, match="timeout"):
            provider.analyze({"findings": []})
        elapsed = time.monotonic() - started

    assert elapsed < 0.5


def test_provider_applies_remaining_deadline_before_response_headers(monkeypatch):
    from app.intelligence import providers

    class FakeSocket:
        def __init__(self, timeout):
            self.timeout = timeout

        def settimeout(self, timeout):
            self.timeout = timeout

    class DeadlineConnection:
        instance = None

        def __init__(self, host, port, timeout):
            self.sock = FakeSocket(timeout)
            type(self).instance = self

        def request(self, method, path, body, headers):
            return None

        def getresponse(self):
            if self.sock.timeout < 0.05:
                raise TimeoutError
            raise AssertionError("Response headers received a fresh timeout")

        def close(self):
            return None

    times = iter((0.0, 0.08))
    monkeypatch.setattr(providers, "monotonic", lambda: next(times))
    monkeypatch.setattr(providers.http.client, "HTTPConnection", DeadlineConnection)
    provider = OpenAICompatibleProvider(
        base_url="http://127.0.0.1:9999/v1",
        model="test-model",
        timeout_seconds=0.1,
        sends_data_external=False,
    )

    with pytest.raises(ProviderError, match="fixed timeout"):
        provider.analyze({"findings": []})

    assert DeadlineConnection.instance is not None
    assert DeadlineConnection.instance.sock.timeout == pytest.approx(0.02)


@pytest.mark.parametrize("mode", ["trickle_headers", "trickle_chunk_size"])
def test_provider_enforces_deadline_during_http_framing(mode):
    with provider_server(mode) as port:
        provider = OpenAICompatibleProvider(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="test-model",
            timeout_seconds=0.1,
            sends_data_external=False,
        )
        started = time.monotonic()
        with pytest.raises(ProviderError, match="timeout"):
            provider.analyze({"findings": []})
        elapsed = time.monotonic() - started

    assert elapsed < 0.5


def test_provider_bounds_fragmented_chunked_response_work():
    with provider_server("many_chunks") as port:
        provider = OpenAICompatibleProvider(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="test-model",
            timeout_seconds=2,
            sends_data_external=False,
        )
        with pytest.raises(ProviderError, match="fragmented beyond the fixed limit"):
            provider.analyze({"findings": []})


def test_deadline_reader_counts_raw_http_framing_bytes(monkeypatch):
    from app.intelligence import providers

    class FakeSocket:
        def settimeout(self, timeout):
            return None

    monkeypatch.setattr(providers, "MAX_PROVIDER_WIRE_BYTES", 8)
    reader = _DeadlineReader(io.BytesIO(b"0123456789ab"), FakeSocket(), time.monotonic() + 1)
    buffer = bytearray(4)

    assert reader.readinto(buffer) == 4
    assert reader.readinto(buffer) == 4
    with pytest.raises(ProviderError, match="wire-size limit"):
        reader.readinto(buffer)
