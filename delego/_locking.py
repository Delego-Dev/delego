"""A small cross-process file lock for serialising writes to file-backed state.

The audit ledger and the approval queue are read-modify-write: appending a
receipt reads the last one (for ``seq`` and ``prev_hash``) before writing, and
deciding an approval reads its status before writing the new one. Two writers
racing that window can fork the hash chain or interleave a torn line. Until the
single-writer daemon lands, an exclusive OS lock makes each such section atomic
*across processes*, so concurrent agents writing to the same delego home cannot
corrupt the ledger or the approval store.

This guards write **integrity** (no forked chains, no torn records). It does not
make the rate-limit count exact under concurrency — that count→execute→append
window spans the broker call and is closed only by the single-writer daemon.

POSIX uses ``fcntl.flock``; Windows uses ``msvcrt.locking`` (best effort). The
lock is taken on a sidecar ``<file>.lock`` so it is independent of the data file
being rewritten, and blocks until acquired.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:  # POSIX (Linux, macOS)
    import fcntl

    def _acquire(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _release(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

except ImportError:  # Windows
    import msvcrt

    def _acquire(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _release(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def file_lock(target: os.PathLike | str) -> Iterator[None]:
    """Hold an exclusive lock for the duration of the ``with`` block.

    ``target`` is the data file being protected; the lock itself lives on
    ``<target>.lock`` next to it. Not re-entrant — never nest two ``file_lock``
    calls on the same target in one thread.
    """
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        _acquire(fd)
        yield
    finally:
        try:
            _release(fd)
        finally:
            os.close(fd)
