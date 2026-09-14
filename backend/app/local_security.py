"""Small, local-only authorization boundary for unsafe HTTP requests."""

import hashlib
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections import deque
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path

from starlette.requests import Request

logger = logging.getLogger("reddock.local_security")

LOCAL_OPERATOR_RUNTIME_STATE = "local_operator_runtime"
OPERATOR_COOKIE_NAME = "reddock_operator"
OPERATOR_HEADER_NAME = "X-RedDock-Operator-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ALLOWED_BROWSER_ORIGINS = frozenset(
    {"http://localhost:8080", "http://127.0.0.1:8080"}
)

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_TOKEN_BYTES = 32
_MAX_TOKEN_FILE_BYTES = 256
_MUTATION_LIMIT = 120
_MUTATION_WINDOW_SECONDS = 60.0
_UNLOCK_LIMIT = 10
_UNLOCK_WINDOW_SECONDS = 60.0


class LocalOperatorUnavailable(RuntimeError):
    """The local operator boundary is unavailable and must fail closed."""


class LocalMutationDenied(RuntimeError):
    """An unsafe local request did not prove operator authorization."""


class LocalMutationThrottled(RuntimeError):
    """The fixed in-process mutation allowance has been consumed."""


class _FixedWindowThrottle:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.__limit = limit
        self.__window_seconds = window_seconds
        self.__events: deque[float] = deque()
        self.__lock = threading.Lock()

    def consume(self, now: float | None = None) -> None:
        moment = time.monotonic() if now is None else now
        cutoff = moment - self.__window_seconds
        with self.__lock:
            while self.__events and self.__events[0] <= cutoff:
                self.__events.popleft()
            if len(self.__events) >= self.__limit:
                raise LocalMutationThrottled()
            self.__events.append(moment)


@dataclass(frozen=True, slots=True)
class LocalOperatorStartup:
    runtime: "LocalOperatorRuntime"
    created_token: str | None


class LocalOperatorRuntime:
    """Hold only a token digest plus bounded process-local admission state."""

    def __init__(self, token: str | None, token_path: Path) -> None:
        self.__digest = _digest(token) if token is not None else None
        self.__token_path = token_path
        self.__mutations = _FixedWindowThrottle(
            _MUTATION_LIMIT, _MUTATION_WINDOW_SECONDS
        )
        self.__unlocks = _FixedWindowThrottle(_UNLOCK_LIMIT, _UNLOCK_WINDOW_SECONDS)

    @property
    def available(self) -> bool:
        return self.__file_matches()

    def verify(self, candidate: str | None) -> bool:
        if self.__digest is None or candidate is None or not _TOKEN_PATTERN.fullmatch(candidate):
            return False
        return compare_digest(self.__digest, _digest(candidate))

    def authorize_mutation(self, request: Request) -> None:
        self.__require_available()
        if not origin_allowed(request):
            raise LocalMutationDenied()
        if not self.verify(operator_credential(request)):
            raise LocalMutationDenied()
        self.__mutations.consume()

    def authorize_unlock(self, request: Request, candidate: str) -> None:
        self.__require_available()
        if not origin_allowed(request):
            raise LocalMutationDenied()
        self.__unlocks.consume()
        if not self.verify(candidate):
            raise LocalMutationDenied()

    def request_is_unlocked(self, request: Request) -> bool:
        return self.__file_matches() and self.verify(operator_credential(request))

    def __require_available(self) -> None:
        if not self.__file_matches():
            raise LocalOperatorUnavailable()

    def __file_matches(self) -> bool:
        if self.__digest is None:
            return False
        try:
            return compare_digest(self.__digest, _digest(_read_token(self.__token_path)))
        except LocalOperatorUnavailable:
            return False


def load_or_create_local_operator(path: Path) -> LocalOperatorStartup:
    """Load a valid token, or create it once for an uninitialized data volume."""

    token_path = Path(os.path.abspath(path))
    marker_path = token_path.with_name(f"{token_path.name}.initialized")
    token_path.parent.mkdir(parents=True, exist_ok=True)

    if token_path.exists() or token_path.is_symlink():
        token = _read_token(token_path)
        _ensure_marker(marker_path)
        return LocalOperatorStartup(LocalOperatorRuntime(token, token_path), None)
    if marker_path.exists() or marker_path.is_symlink():
        logger.error(
            "Local operator token is missing after initialization; unsafe requests are disabled"
        )
        return LocalOperatorStartup(LocalOperatorRuntime(None, token_path), None)

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    if not _TOKEN_PATTERN.fullmatch(token):
        raise LocalOperatorUnavailable("generated operator token has an invalid shape")
    _write_private_file(token_path, token.encode("ascii") + b"\n")
    _ensure_marker(marker_path)
    return LocalOperatorStartup(LocalOperatorRuntime(token, token_path), token)


def origin_allowed(request: Request) -> bool:
    """Accept CLI requests without Origin and browsers only from the fixed local UI."""

    origins = request.headers.getlist("origin")
    return not origins or (len(origins) == 1 and origins[0] in ALLOWED_BROWSER_ORIGINS)


def operator_credential(request: Request) -> str | None:
    header_values = request.headers.getlist(OPERATOR_HEADER_NAME)
    cookie_values: list[str] = []
    for raw_cookie in request.headers.getlist("cookie"):
        for item in raw_cookie.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == OPERATOR_COOKIE_NAME:
                cookie_values.append(value)
    if len(header_values) + len(cookie_values) != 1:
        return None
    return (header_values + cookie_values)[0]


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def _read_token(path: Path) -> str:
    descriptor = -1
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise LocalOperatorUnavailable("operator token must be a regular, non-symlink file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LocalOperatorUnavailable("operator token must be a regular, non-symlink file")
        if not 1 <= metadata.st_size <= _MAX_TOKEN_FILE_BYTES:
            raise LocalOperatorUnavailable("operator token file has an invalid size")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise LocalOperatorUnavailable("operator token file permissions must be 0600")
        token = (
            os.read(descriptor, _MAX_TOKEN_FILE_BYTES + 1)
            .decode("ascii")
            .removesuffix("\n")
        )
    except LocalOperatorUnavailable:
        raise
    except (OSError, UnicodeError):
        raise LocalOperatorUnavailable("operator token could not be read safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not _TOKEN_PATTERN.fullmatch(token):
        raise LocalOperatorUnavailable("operator token has an invalid shape")
    return token


def _ensure_marker(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise LocalOperatorUnavailable("operator initialization marker is unsafe")
        return
    _write_private_file(path, b"initialized\n")


def _write_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
