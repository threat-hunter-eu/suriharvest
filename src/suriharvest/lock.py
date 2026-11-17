"""Workspace lock: one writer (sync, index, validate) at a time. Readers (search, show, web) do not lock.

The lock is released by the OS when the process dies, so a crash never leaves a stale lock behind. The file records
who holds it, for the error message.

POSIX: an flock on data/suriharvest.lock. Windows: a one-byte msvcrt lock far past the holder text. Windows
byte-range locks are mandatory, so locking byte 0 would stop a second process from reading who holds the lock.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

# Windows: the locked byte. Locking past the end of the file is allowed and leaves the holder text readable.
_WIN_LOCK_OFFSET = 1 << 20


class LockBusy(RuntimeError):
    pass


if os.name == "nt":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, _WIN_LOCK_OFFSET, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        os.lseek(fd, _WIN_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _read_holder(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    return text.strip("\x00 \r\n\t") or "another suriharvest process"


@contextmanager
def workspace_lock(data_dir: Path, what: str, wait: float = 0.0) -> Iterator[None]:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "suriharvest.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o644)
    deadline = time.monotonic() + wait
    locked = False
    try:
        while True:
            if _try_lock(fd):
                locked = True
                break
            if time.monotonic() >= deadline:
                raise LockBusy(f"workspace is busy: {_read_holder(path)}")
            time.sleep(0.5)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"pid {os.getpid()}: {what}\n".encode())
        yield
    finally:
        if locked:
            with suppress(OSError):
                os.ftruncate(fd, 0)
            with suppress(OSError):
                _unlock(fd)
        os.close(fd)
