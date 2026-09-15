"""Clear RAM: trim the working sets of every process we are allowed to touch.

What this really does: each process's resident pages are moved off physical RAM onto the
standby/modified lists (``EmptyWorkingSet``). "In use" memory drops immediately and the RAM meter
falls. Nothing is closed or lost: when a program touches those pages again they are faulted back
in, usually from the standby list without disk I/O, so the cost is a brief slowdown in programs
that were idle. It is the same operation as Sysinternals RAMMap's "Empty Working Sets".

It does **not** purge the standby list (that would throw away the file cache and needs
Administrator plus ``SeProfileSingleProcessPrivilege``), and it never touches kernel
pseudo-processes. Access is per process: a standard user trims only their own processes.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final

import psutil

from winsentinel.utils import windows

SKIPPED_PIDS: Final = frozenset({0, 4})  # System Idle Process and System cannot be opened


@dataclass(frozen=True, slots=True)
class MemoryTrimResult:
    trimmed: int  # processes whose working set was emptied
    denied: int  # access denied (other users' / SYSTEM / protected processes)
    gone: int  # exited before we reached them, or otherwise unopenable
    used_before: int  # bytes in use before
    used_after: int  # bytes in use after
    duration_seconds: float

    @property
    def freed_bytes(self) -> int:
        return max(0, self.used_before - self.used_after)


def _used_bytes() -> int:
    return int(psutil.virtual_memory().used)


class MemoryTrimmer:
    def __init__(
        self,
        *,
        trim: Callable[[int], None] = windows.empty_working_set,
        pids: Callable[[], Iterable[int]] = psutil.pids,
        used_bytes: Callable[[], int] = _used_bytes,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._trim = trim
        self._pids = pids
        self._used = used_bytes
        self._monotonic = monotonic

    def trim_all(self) -> MemoryTrimResult:
        started = self._monotonic()
        before = self._used()
        trimmed = denied = gone = 0
        for pid in self._pids():
            if pid in SKIPPED_PIDS:
                continue
            try:
                self._trim(pid)
            except OSError as exc:
                if getattr(exc, "winerror", None) == windows.ERROR_ACCESS_DENIED:
                    denied += 1
                else:
                    gone += 1
                continue
            trimmed += 1
        return MemoryTrimResult(
            trimmed=trimmed,
            denied=denied,
            gone=gone,
            used_before=before,
            used_after=self._used(),
            duration_seconds=round(self._monotonic() - started, 3),
        )
