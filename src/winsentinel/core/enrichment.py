"""Background enrichment: SHA256 and Authenticode signature for observed processes.

Hashing and ``WinVerifyTrust`` are I/O-bound and can take hundreds of milliseconds for large
binaries the first time (results are cached per file fingerprint afterwards). Doing that inside
the process monitor would stall collection, so enrichment runs on its own low-priority thread:

    PROCESS_STARTED / PROCESS_DISCOVERED ──▶ request(key) ──▶ worker ──▶ state.set_enrichment()
                                                                     └─▶ PROCESS_ENRICHED event

Newly started processes are served before the startup inventory, so a fresh suspicious process is
not queued behind 300 already-running ones. Both queues are bounded; overflow is counted.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable
from typing import Final

from winsentinel.collectors.process_collector import ProcessEnricher
from winsentinel.core.models import (
    ComponentHealth,
    ComponentStatus,
    EventType,
    FieldIssue,
    SecurityEvent,
)
from winsentinel.core.state import SystemState
from winsentinel.utils import windows
from winsentinel.utils.time import utc_now

logger = logging.getLogger(__name__)

SOURCE: Final = "enrichment"
_WAIT_SECONDS: Final = 0.5
_ENRICHMENT_ISSUE_FIELDS: Final = ("sha256",)


class EnrichmentWorker:
    name: Final = "enrichment"

    def __init__(
        self,
        enricher: ProcessEnricher,
        state: SystemState,
        publish: Callable[[SecurityEvent], bool],
        *,
        capacity: int = 4096,
        background_priority: bool = True,
    ) -> None:
        self._enricher = enricher
        self._state = state
        self._publish = publish
        self._capacity = capacity
        self._background = background_priority
        self._urgent: deque[str] = deque()
        self._inventory: deque[str] = deque()
        self._pending: set[str] = set()
        self._condition = threading.Condition()
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._enriched = 0
        self._dropped = 0
        self._errors = 0
        self._last_error: str | None = None

    def request(self, process_key: str, *, urgent: bool) -> None:
        with self._condition:
            if process_key in self._pending or self._stopping:
                return
            if len(self._pending) >= self._capacity:
                self._dropped += 1
                return
            (self._urgent if urgent else self._inventory).append(process_key)
            self._pending.add(process_key)
            self._condition.notify()

    def on_event(self, event: SecurityEvent) -> None:
        """Bus handler for process lifecycle events."""
        if event.process_key is None or not event.data.get("exe"):
            return
        self.request(event.process_key, urgent=event.event_type is EventType.PROCESS_STARTED)

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="winsentinel-enrichment", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float) -> bool:
        """Stop after the current item; queued work is abandoned (it is recomputable)."""
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        if self._thread is not None:
            self._thread.join(timeout)
            return not self._thread.is_alive()
        return True

    def process_pending(self, max_items: int | None = None) -> int:
        """Synchronously enrich queued processes on the calling thread (tests)."""
        done = 0
        while max_items is None or done < max_items:
            key = self._next(block=False)
            if key is None:
                return done
            self._enrich(key)
            done += 1
        return done

    def health(self) -> ComponentHealth:
        with self._condition:
            queued = len(self._pending)
            status = ComponentStatus.OK
            if self._thread is not None and not self._thread.is_alive():
                status = ComponentStatus.STOPPED
            elif self._errors and self._last_error:
                status = ComponentStatus.DEGRADED
            return ComponentHealth(
                name=self.name,
                status=status,
                runs=self._enriched,
                failures=self._errors,
                last_error=self._last_error,
                detail=f"{queued} queued, {self._dropped} dropped",
            )

    @property
    def enriched(self) -> int:
        with self._condition:
            return self._enriched

    def _run(self) -> None:
        if self._background and not windows.enter_background_mode():
            logger.debug("event=BACKGROUND_MODE_UNAVAILABLE")
        while True:
            key = self._next(block=True)
            if key is None:
                return
            self._enrich(key)

    def _next(self, *, block: bool) -> str | None:
        with self._condition:
            while not self._urgent and not self._inventory:
                if self._stopping or not block:
                    return None
                self._condition.wait(_WAIT_SECONDS)
            if self._stopping and block:
                return None
            key = self._urgent.popleft() if self._urgent else self._inventory.popleft()
            self._pending.discard(key)
            return key

    def _enrich(self, key: str) -> None:
        info = self._state.process(key)
        if info is None or info.exe is None:
            return
        try:
            enriched = self._enricher.enrich(info)
        except Exception as exc:  # enrichment must never kill the worker
            with self._condition:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("event=ENRICHMENT_FAILED pid=%s error=%s", info.pid, exc)
            return
        issues: dict[str, FieldIssue] = {
            k: v for k, v in enriched.unavailable.items() if k in _ENRICHMENT_ISSUE_FIELDS
        }
        self._state.set_enrichment(key, enriched.sha256, enriched.signature, issues)
        with self._condition:
            self._enriched += 1
        signature = enriched.signature
        self._publish(
            SecurityEvent(
                event_type=EventType.PROCESS_ENRICHED,
                timestamp=utc_now(),
                source=SOURCE,
                process_key=key,
                pid=info.pid,
                data={
                    "name": info.name,
                    "exe": info.exe,
                    "sha256": enriched.sha256,
                    "signature_status": signature.status.value if signature else None,
                    "signature_source": signature.source.value if signature else None,
                    "signer": signature.signer if signature else None,
                    "signature_detail": signature.detail if signature else None,
                },
            )
        )
