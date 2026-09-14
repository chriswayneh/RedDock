"""Fixed Unix-socket entrypoint and readiness check for the Compose boundary."""

import http.client
import os
import socket
import stat
import sys
from pathlib import Path

SOCKET_PATH = Path("/run/reddock-api/reddock.sock")


class _UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(str(SOCKET_PATH))
        self.sock = connection


def serve() -> None:
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        metadata = SOCKET_PATH.lstat()
        if not stat.S_ISSOCK(metadata.st_mode):
            raise RuntimeError("Refusing to replace a non-socket API path")
        SOCKET_PATH.unlink()
    os.execvp(
        "uvicorn",
        (
            "uvicorn",
            "app.main:app",
            "--uds",
            str(SOCKET_PATH),
            "--no-proxy-headers",
        ),
    )


def check() -> None:
    connection = _UnixHTTPConnection("localhost", timeout=2)
    try:
        connection.request("GET", "/api/ready", headers={"Host": "localhost"})
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError("RedDock is not ready")
    finally:
        connection.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        serve()
    elif sys.argv[1:] == ["check"]:
        check()
    else:
        raise SystemExit("usage: python -m app.compose_socket {serve|check}")
