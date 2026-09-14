"""Process lifetime lock used to prove offline maintenance is actually offline."""

from __future__ import annotations

import os
import stat
from pathlib import Path

LOCK_NAME = ".reddock-instance.lock"


class InstanceLockError(RuntimeError):
    """The RedDock data directory is already owned by a running process."""


class InstanceLock:
    def __init__(self, descriptor: int):
        self._descriptor = descriptor

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, -1
        if descriptor < 0:
            return
        _unlock(descriptor)
        os.close(descriptor)


def acquire_instance_lock(path: Path) -> InstanceLock:
    """Acquire and retain the exclusive process lock, refusing links and peers."""

    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise InstanceLockError("RedDock instance lock could not be opened safely") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InstanceLockError("RedDock instance lock must be a regular file")
        _lock(descriptor)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        return InstanceLock(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def verify_instance_offline(data_dir: Path) -> None:
    """Prove no RedDock process holds the data-directory lifetime lock."""

    path = data_dir / LOCK_NAME
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise InstanceLockError("RedDock instance lock must not be a link")
    except FileNotFoundError:
        # Data created before the lock existed has no running new-version process.
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InstanceLockError(
            "RedDock instance lock could not be inspected safely"
        ) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InstanceLockError("RedDock instance lock must be a regular file")
        _lock(descriptor)
        _unlock(descriptor)
    finally:
        os.close(descriptor)


def _lock(descriptor: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise InstanceLockError(
            "RedDock is still running against this data directory; stop it before maintenance"
        ) from error


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)
