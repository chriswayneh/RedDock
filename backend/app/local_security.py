"""Small, local-only authorization boundary for unsafe HTTP requests."""

import hashlib
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path

from starlette.requests import Request

logger = logging.getLogger("reddock.local_security")

LOCAL_OPERATOR_RUNTIME_STATE = "local_operator_runtime"
OPERATOR_COOKIE_NAME = "reddock_operator"
OPERATOR_HEADER_NAME = "X-RedDock-Operator-Token"
OPERATOR_CSRF_HEADER_NAME = "X-RedDock-Operator-CSRF"
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
BROWSER_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60
_BROWSER_SESSION_IDLE_SECONDS = 30 * 60
_MAX_BROWSER_SESSIONS = 8


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


@dataclass(frozen=True, slots=True)
class IssuedLocalBrowserSession:
    token: str
    session_id: str
    csrf_token: str


@dataclass(slots=True)
class _LocalBrowserSession:
    session_id: str
    csrf_digest: bytes
    created_at: float
    last_seen_at: float


class LocalOperatorRuntime:
    """Hold only a token digest plus bounded process-local admission state."""

    def __init__(self, token: str | None, token_path: Path) -> None:
        self.__digest = _digest(token) if token is not None else None
        self.__token_path = token_path
        self.__mutations = _FixedWindowThrottle(
            _MUTATION_LIMIT, _MUTATION_WINDOW_SECONDS
        )
        self.__unlocks = _FixedWindowThrottle(_UNLOCK_LIMIT, _UNLOCK_WINDOW_SECONDS)
        self.__sessions: OrderedDict[bytes, _LocalBrowserSession] = OrderedDict()
        self.__session_lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self.__file_matches()

    def verify(self, candidate: str | None) -> bool:
        if self.__digest is None or candidate is None or not _TOKEN_PATTERN.fullmatch(candidate):
            return False
        return compare_digest(self.__digest, _digest(candidate))

    def authorize_mutation(self, request: Request) -> None:
        self.__require_available()
        origins = request.headers.getlist("origin")
        header_values = request.headers.getlist(OPERATOR_HEADER_NAME)
        cookie_values = _operator_cookie_values(request)
        csrf_values = request.headers.getlist(OPERATOR_CSRF_HEADER_NAME)
        if not origins:
            if (
                len(header_values) != 1
                or cookie_values
                or csrf_values
                or not self.verify(header_values[0])
            ):
                raise LocalMutationDenied()
        elif (
            not browser_origin_allowed(request)
            or header_values
            or len(cookie_values) != 1
            or len(csrf_values) != 1
            or not self.__verify_browser_session(
                cookie_values[0], csrf_values[0], touch=True
            )
        ):
            raise LocalMutationDenied()
        self.__mutations.consume()

    def authorize_unlock(
        self, request: Request, candidate: str
    ) -> IssuedLocalBrowserSession:
        self.__require_available()
        if not browser_origin_allowed(request):
            raise LocalMutationDenied()
        self.__unlocks.consume()
        if not self.verify(candidate):
            raise LocalMutationDenied()
        return self.__issue_browser_session()

    def request_is_unlocked(self, request: Request) -> bool:
        return self.request_browser_session_id(request) is not None

    def request_browser_session_id(self, request: Request) -> str | None:
        """Return the public identifier for the request's active browser session."""

        if not self.__file_matches():
            self.__clear_browser_sessions()
            return None
        cookie_values = _operator_cookie_values(request)
        if len(cookie_values) != 1:
            return None
        return self.__browser_session_id(cookie_values[0])

    def __require_available(self) -> None:
        if not self.__file_matches():
            self.__clear_browser_sessions()
            raise LocalOperatorUnavailable()

    def __issue_browser_session(self) -> IssuedLocalBrowserSession:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session_id = secrets.token_urlsafe(_TOKEN_BYTES)
        csrf_token = secrets.token_urlsafe(_TOKEN_BYTES)
        if not all(
            _TOKEN_PATTERN.fullmatch(value)
            for value in (token, session_id, csrf_token)
        ):
            raise LocalOperatorUnavailable("generated browser credentials have an invalid shape")
        moment = time.monotonic()
        with self.__session_lock:
            self.__purge_browser_sessions(moment)
            while len(self.__sessions) >= _MAX_BROWSER_SESSIONS:
                self.__sessions.popitem(last=False)
            self.__sessions[_digest(token)] = _LocalBrowserSession(
                session_id=session_id,
                csrf_digest=_digest(csrf_token),
                created_at=moment,
                last_seen_at=moment,
            )
        return IssuedLocalBrowserSession(
            token=token,
            session_id=session_id,
            csrf_token=csrf_token,
        )

    def __browser_session_id(self, token: str) -> str | None:
        if not _TOKEN_PATTERN.fullmatch(token):
            return None
        token_digest = _digest(token)
        moment = time.monotonic()
        with self.__session_lock:
            self.__purge_browser_sessions(moment)
            matching_digest = self.__matching_session_digest(token_digest)
            if matching_digest is None:
                return None
            return self.__sessions[matching_digest].session_id

    def __verify_browser_session(
        self, token: str, csrf_token: str | None, *, touch: bool
    ) -> bool:
        if not _TOKEN_PATTERN.fullmatch(token):
            return False
        if csrf_token is not None and not _TOKEN_PATTERN.fullmatch(csrf_token):
            return False
        token_digest = _digest(token)
        moment = time.monotonic()
        with self.__session_lock:
            self.__purge_browser_sessions(moment)
            matching_digest = self.__matching_session_digest(token_digest)
            if matching_digest is None:
                return False
            session = self.__sessions[matching_digest]
            if csrf_token is not None and not compare_digest(
                session.csrf_digest, _digest(csrf_token)
            ):
                return False
            if touch:
                session.last_seen_at = moment
                self.__sessions.move_to_end(matching_digest)
            return True

    def __matching_session_digest(self, token_digest: bytes) -> bytes | None:
        return next(
            (
                digest
                for digest in self.__sessions
                if compare_digest(digest, token_digest)
            ),
            None,
        )

    def __purge_browser_sessions(self, moment: float) -> None:
        expired = [
            digest
            for digest, session in self.__sessions.items()
            if session.created_at + BROWSER_SESSION_MAX_AGE_SECONDS <= moment
            or session.last_seen_at + _BROWSER_SESSION_IDLE_SECONDS <= moment
        ]
        for digest in expired:
            del self.__sessions[digest]

    def __clear_browser_sessions(self) -> None:
        with self.__session_lock:
            self.__sessions.clear()

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


def browser_origin_allowed(request: Request) -> bool:
    """Accept an exact RedDock browser origin and reject non-browser unlocks."""

    origins = request.headers.getlist("origin")
    return len(origins) == 1 and origins[0] in ALLOWED_BROWSER_ORIGINS


def _operator_cookie_values(request: Request) -> list[str]:
    values: list[str] = []
    for raw_cookie in request.headers.getlist("cookie"):
        for item in raw_cookie.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == OPERATOR_COOKIE_NAME:
                values.append(value)
    return values


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
