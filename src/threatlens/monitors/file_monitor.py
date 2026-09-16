"""Event-driven file monitor for security-relevant locations (Phase 12).

Uses ``watchdog`` (``ReadDirectoryChangesW`` under the hood) to watch a *small, configured* set of
directories — Startup folders, ``%TEMP%``, Downloads by default — and emit ``FILE_CREATED`` /
``FILE_MODIFIED`` / ``FILE_DELETED`` events. It never recursively watches all of ``C:\\`` (spec
§14): that would be noisy and expensive.

Design:
    * Event-driven, not polling: watchdog delivers changes on its own observer thread; this class
      converts them to :class:`SecurityEvent`s and hands them to the engine's ``publish`` callback
      (the bus is thread-safe).
    * Rapid ``MODIFIED`` bursts (editors, temp writes) are debounced per path so a single save does
      not flood the bus.
    * Failures to watch a path (missing, access denied) are recorded, not fatal.
"""

from __future__ import annotations

import logging
import ntpath
import os
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Final

from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from threatlens.core.models import ComponentHealth, ComponentStatus, EventType, SecurityEvent
from threatlens.utils.time import utc_now

logger = logging.getLogger(__name__)

SOURCE: Final = "file_monitor"
_MODIFY_DEBOUNCE_SECONDS: Final = 1.0
EXECUTABLE_EXTENSIONS: Final = frozenset(
    {".exe", ".dll", ".scr", ".com", ".pif", ".cmd", ".bat", ".ps1", ".vbs", ".js", ".jse",
     ".wsf", ".hta", ".jar", ".msi", ".lnk"}
)  # fmt: skip

Publish = Callable[[SecurityEvent], object]


def default_monitored_paths() -> list[Path]:
    """Safe defaults: Startup folders, the user's Temp, and Downloads."""
    startup = r"Microsoft\Windows\Start Menu\Programs\Startup"
    appdata, program_data = os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")
    profile = os.environ.get("USERPROFILE")
    candidates: list[Path | None] = [
        Path(appdata) / startup if appdata else None,
        Path(program_data) / startup if program_data else None,
        Path(os.environ["TEMP"]) if os.environ.get("TEMP") else None,
        Path(profile) / "Downloads" if profile else None,
    ]
    seen: dict[str, Path] = {}
    for path in candidates:
        if path is not None and path.is_dir():
            seen.setdefault(str(path).lower(), path)
    return list(seen.values())


def _extension(path: str) -> str:
    return ntpath.splitext(path)[1].lower()


def is_executable_or_script(path: str) -> bool:
    return _extension(path) in EXECUTABLE_EXTENSIONS


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: FileMonitor) -> None:
        self._monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.emit(EventType.FILE_CREATED, str(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.emit(EventType.FILE_DELETED, str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.emit(EventType.FILE_MODIFIED, str(event.src_path), debounce=True)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.emit(
                EventType.FILE_RENAMED, str(event.dest_path), extra={"from": str(event.src_path)}
            )


class FileMonitor:
    name: Final = "file_monitor"

    def __init__(self, publish: Publish, paths: Iterable[Path] | None = None) -> None:
        self._publish = publish
        self._paths = list(paths) if paths is not None else default_monitored_paths()
        self._observer: Observer | None = None  # type: ignore[valid-type]
        self._watched: list[str] = []
        self._unavailable: list[str] = []
        self._recent_modified: dict[str, float] = {}
        self._lock = threading.Lock()
        self._events = 0
        self._monotonic: Callable[[], float] = time.monotonic

    def start(self) -> None:
        observer = Observer()
        for path in self._paths:
            try:
                observer.schedule(_Handler(self), str(path), recursive=True)
                self._watched.append(str(path))
            except (OSError, FileNotFoundError) as exc:
                self._unavailable.append(str(path))
                logger.debug("event=FILE_WATCH_FAILED path=%s error=%s", path, exc)
        if self._watched:
            observer.start()
            self._observer = observer

    def stop(self, timeout: float = 3.0) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout)
            self._observer = None

    def emit(
        self,
        event_type: EventType,
        path: str,
        *,
        debounce: bool = False,
        extra: dict[str, object] | None = None,
    ) -> None:
        if debounce and self._is_debounced(path):
            return
        with self._lock:
            self._events += 1
        data = {
            "path": path,
            "name": ntpath.basename(path),
            "extension": _extension(path),
            "executable_or_script": is_executable_or_script(path),
            **(extra or {}),
        }
        self._publish(
            SecurityEvent(event_type=event_type, timestamp=utc_now(), source=SOURCE, data=data)
        )

    def _is_debounced(self, path: str) -> bool:
        now = self._monotonic()
        with self._lock:
            last = self._recent_modified.get(path, 0.0)
            self._recent_modified[path] = now
            if len(self._recent_modified) > 4096:
                self._recent_modified = {
                    p: t for p, t in self._recent_modified.items() if now - t < 60
                }
            return now - last < _MODIFY_DEBOUNCE_SECONDS

    def health(self) -> ComponentHealth:
        if not self._watched:
            return ComponentHealth(
                name=self.name,
                status=ComponentStatus.UNAVAILABLE,
                detail="no monitored paths are accessible",
            )
        status = ComponentStatus.DEGRADED if self._unavailable else ComponentStatus.OK
        detail = f"watching {len(self._watched)} paths, {self._events} events"
        if self._unavailable:
            detail += f", unavailable: {', '.join(self._unavailable)}"
        return ComponentHealth(name=self.name, status=status, runs=self._events, detail=detail)
