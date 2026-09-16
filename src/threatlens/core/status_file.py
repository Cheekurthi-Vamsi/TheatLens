"""Engine status file and single-instance lock.

A running ``threatlens monitor`` periodically writes :class:`EngineStatus` to
``%LOCALAPPDATA%\\ThreatLens\\engine-status.json``; ``threatlens status`` (a separate process)
reads it. This gives cross-process observability without a server or IPC endpoint.

Safety:
    * Writes are **atomic**: a temporary file in the same directory is written and then renamed
      over the target with ``os.replace`` (``MoveFileEx`` with replace semantics), so a reader
      never sees half a file and a crash never corrupts it.
    * The reader treats the file as **untrusted**: size-limited and schema-validated; anything
      malformed is reported as "no status" rather than trusted or crashed on.
    * A status is only believed if it is fresh *and* the PID still belongs to the same process
      instance (``process_key``), so a stale file from a crashed engine is never shown as running.

Single instance: :class:`InstanceLock` holds an exclusive byte-range lock (``msvcrt.locking``,
i.e. ``LockFile``) on ``engine.lock`` for the engine's lifetime. Windows releases the lock
automatically when the process exits, even if it crashes, so there are no stale locks to clean up.
"""

from __future__ import annotations

import contextlib
import logging
import msvcrt
import os
from datetime import datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from pydantic import ValidationError

from threatlens.config import app_data_dir
from threatlens.core.models import EngineState, EngineStatus
from threatlens.errors import ThreatLensError

logger = logging.getLogger(__name__)

STATUS_FILE_NAME: Final = "engine-status.json"
LOCK_FILE_NAME: Final = "engine.lock"
MAX_STATUS_BYTES: Final = 1024 * 1024


def default_status_path() -> Path:
    return app_data_dir() / STATUS_FILE_NAME


class EngineAlreadyRunningError(ThreatLensError):
    """Another monitor instance holds the engine lock."""


class StatusFile:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, status: EngineStatus) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        temporary.write_text(status.model_dump_json(), encoding="utf-8")
        temporary.replace(self.path)  # atomic rename-over (MoveFileExW with REPLACE_EXISTING)

    def read(self) -> EngineStatus | None:
        try:
            if self.path.stat().st_size > MAX_STATUS_BYTES:
                logger.warning("event=STATUS_FILE_TOO_LARGE path=%s", self.path)
                return None
            return EngineStatus.model_validate_json(self.path.read_bytes())
        except FileNotFoundError:
            return None
        except (OSError, ValueError, ValidationError) as exc:
            logger.warning("event=STATUS_FILE_INVALID path=%s error=%s", self.path, exc)
            return None


def is_status_current(
    status: EngineStatus,
    now: datetime,
    *,
    stale_after: timedelta,
    process_alive: bool,
) -> bool:
    """A status describes a live engine only if recent, not stopped, and its process still runs."""
    if status.state is EngineState.STOPPED or not process_alive:
        return False
    return now - status.updated_at <= stale_after


class InstanceLock:
    """Exclusive, crash-safe lock ensuring one engine per user profile."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            raise EngineAlreadyRunningError(
                "Another ThreatLens monitor is already running for this user "
                f"(lock held on {self.path}). Use 'threatlens status' to see it."
            ) from None
        self._fd = fd
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fd is None:
            return
        with contextlib.suppress(OSError):
            os.lseek(self._fd, 0, os.SEEK_SET)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        os.close(self._fd)
        self._fd = None
