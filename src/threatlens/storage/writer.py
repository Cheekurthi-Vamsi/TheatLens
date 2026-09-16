"""Single-threaded, batched database writer.

SQLite allows one writer at a time, so all writes for a running engine funnel through this one
thread and its one connection. It batches (every ~500 ms or 200 items) inside a transaction for
throughput, and on shutdown drains the queue, commits, checkpoints the WAL and closes cleanly —
so Ctrl+C never leaves a corrupt or half-written database.

The queue is bounded; if the engine ever outruns the disk, the oldest items are dropped and
counted (surfaced in ``threatlens status``) rather than growing memory without bound.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from threatlens.core.models import (
    Alert,
    ComponentHealth,
    ComponentStatus,
    DetectionResult,
    ResponseAction,
    SecurityEvent,
)
from threatlens.storage.database import Database
from threatlens.storage.repositories import SecurityStore

logger = logging.getLogger(__name__)

_FLUSH_INTERVAL: Final = 0.5
_BATCH_SIZE: Final = 200

_Item = tuple[str, object]


@dataclass(frozen=True, slots=True)
class WriterStats:
    written: int
    dropped: int
    errors: int
    queued: int


class DatabaseWriter:
    name: Final = "database_writer"

    def __init__(self, path: Path, *, capacity: int = 50_000) -> None:
        self._path = path
        self._capacity = capacity
        self._queue: deque[_Item] = deque()
        self._condition = threading.Condition()
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._store: SecurityStore | None = None
        self._written = 0
        self._dropped = 0
        self._errors = 0
        self._ready = threading.Event()
        self._open_error: str | None = None

    # -- lifecycle --------------------------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="threatlens-db-writer", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def stop(self, timeout: float) -> bool:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        if self._thread is not None:
            self._thread.join(timeout)
            return not self._thread.is_alive()
        return True

    # -- enqueue (called from the dispatcher / detection / alert threads) --------------------

    def on_event(self, event: SecurityEvent) -> None:
        self._enqueue(("event", event))

    def on_detection(self, detection: DetectionResult) -> None:
        self._enqueue(("detection", detection))

    def on_alert(self, alert: Alert) -> None:
        self._enqueue(("alert", alert))

    def on_action(self, action: ResponseAction) -> None:
        self._enqueue(("action", action))

    def _enqueue(self, item: _Item) -> None:
        with self._condition:
            if self._stopping:
                return
            if len(self._queue) >= self._capacity:
                self._queue.popleft()
                self._dropped += 1
            self._queue.append(item)
            self._condition.notify()

    # -- worker -----------------------------------------------------------------------------

    def _run(self) -> None:
        try:
            db = Database.open(self._path)
        except Exception as exc:  # a broken/locked DB must degrade, not crash the engine
            self._open_error = f"{type(exc).__name__}: {exc}"
            logger.exception("event=DB_OPEN_FAILED path=%s", self._path)
            self._ready.set()
            return
        self._store = SecurityStore(db)
        self._ready.set()
        try:
            while True:
                batch = self._take_batch()
                if batch is None:
                    return
                if batch:
                    self._write_batch(batch)
        finally:
            with self._condition:
                remaining = list(self._queue)
                self._queue.clear()
            if remaining:
                self._write_batch(remaining)
            db.checkpoint()
            db.close()

    def _take_batch(self) -> list[_Item] | None:
        with self._condition:
            while not self._queue and not self._stopping:
                self._condition.wait(_FLUSH_INTERVAL)
            if not self._queue and self._stopping:
                return None
            batch = [self._queue.popleft() for _ in range(min(_BATCH_SIZE, len(self._queue)))]
        return batch

    def _write_batch(self, batch: list[_Item]) -> None:
        store = self._store
        if store is None:
            return
        try:
            with store.db.transaction():
                for kind, obj in batch:
                    self._write_one(store, kind, obj)
            self._written += len(batch)
        except Exception as exc:  # one bad batch must not stop persistence
            self._errors += 1
            logger.warning("event=DB_WRITE_FAILED count=%s error=%s", len(batch), exc)

    @staticmethod
    def _write_one(store: SecurityStore, kind: str, obj: object) -> None:
        if kind == "event" and isinstance(obj, SecurityEvent):
            store.record_event(obj)
        elif kind == "detection" and isinstance(obj, DetectionResult):
            store.record_detection(obj)
        elif kind == "alert" and isinstance(obj, Alert):
            store.upsert_alert(obj)
        elif kind == "action" and isinstance(obj, ResponseAction):
            store.record_action(obj)

    # -- observability ----------------------------------------------------------------------

    def stats(self) -> WriterStats:
        with self._condition:
            return WriterStats(self._written, self._dropped, self._errors, len(self._queue))

    def health(self) -> ComponentHealth:
        stats = self.stats()
        if self._open_error is not None:
            return ComponentHealth(
                name=self.name, status=ComponentStatus.UNAVAILABLE, last_error=self._open_error
            )
        status = ComponentStatus.DEGRADED if stats.errors else ComponentStatus.OK
        return ComponentHealth(
            name=self.name,
            status=status,
            runs=stats.written,
            failures=stats.errors,
            detail=f"{stats.queued} queued, {stats.dropped} dropped",
        )
