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

    def __enter__(self) -> InstanceLock:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


def acquire_instance_lock(path: Path) -> InstanceLock:
    """Acquire and retain the exclusive process lock, refusing links and peers."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        return _acquire_posix_directory_lock(path.parent)

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


def acquire_offline_maintenance_lock(data_dir: Path) -> InstanceLock:
    """Retain exclusive ownership of a data directory for all maintenance work."""

    return acquire_instance_lock(data_dir / LOCK_NAME)


def _acquire_posix_directory_lock(data_dir: Path) -> InstanceLock:
    """Lock the directory inode so a read-only maintenance mount can participate."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(data_dir, flags)
    except OSError as error:
        raise InstanceLockError(
            "RedDock data directory could not be locked safely"
        ) from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise InstanceLockError("RedDock data directory must be a directory")
        _lock(descriptor)
        return InstanceLock(descriptor)
    except Exception:
        os.close(descriptor)
        raise


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
