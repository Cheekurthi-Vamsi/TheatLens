"""Thread-safe in-memory model of the host, shared by monitors, enrichment, rules and status.

What it holds
    * **Current processes** (latest snapshot) and **recently exited** processes, retained for
      ``exit_retention``. Retention matters: ``cmd.exe`` that launched a payload and exited a
      second later must still be resolvable when a rule inspects the payload's lineage.
    * **Enrichment** (SHA256, signature) stored separately from snapshots and merged on read, so a
      fresh snapshot never erases hashing work.
    * **Current sockets**, already correlated to process instances.
    * A short **per-process event history** for temporal correlation.

Concurrency
    Several threads write (process monitor, network monitor, enrichment worker, dispatcher) and
    readers include rules and the status writer. A single re-entrant lock guards everything;
    critical sections are dictionary operations only, and callers receive immutable models.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from threatlens.core.models import (
    CorrelatedConnection,
    FieldIssue,
    ProcessInfo,
    ProcessSnapshot,
    SecurityEvent,
    SignatureInfo,
)
from threatlens.correlation.process_tree import select_parent
from threatlens.utils.time import utc_now


@dataclass(frozen=True, slots=True)
class _Enrichment:
    sha256: str | None
    signature: SignatureInfo | None
    issues: dict[str, FieldIssue]


@dataclass(frozen=True, slots=True)
class StateCounts:
    processes: int
    exited_retained: int
    connections: int
    enriched: int


class SystemState:
    def __init__(
        self,
        *,
        exit_retention: timedelta = timedelta(minutes=5),
        history_per_process: int = 64,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._lock = threading.RLock()
        self._retention = exit_retention
        self._history_size = history_per_process
        self._clock = clock
        self._current: dict[str, ProcessInfo] = {}
        self._current_by_pid: dict[int, str] = {}
        self._exited: dict[str, tuple[ProcessInfo, datetime]] = {}
        self._enrichment: dict[str, _Enrichment] = {}
        self._connections: tuple[CorrelatedConnection, ...] = ()
        self._history: dict[str, deque[SecurityEvent]] = {}

    def now(self) -> datetime:
        return self._clock()

    # -- processes --------------------------------------------------------------------------

    def apply_process_snapshot(self, snapshot: ProcessSnapshot) -> None:
        """Replace the current process table; move vanished processes to the exited set."""
        with self._lock:
            incoming = snapshot.by_key()
            for key, info in self._current.items():
                if key not in incoming:
                    self._exited[key] = (info, snapshot.timestamp)
            for key in incoming:
                self._exited.pop(key, None)
            self._current = incoming
            self._current_by_pid = {p.pid: p.process_key for p in incoming.values()}
            self._prune(snapshot.timestamp)

    def observe_process(self, info: ProcessInfo) -> None:
        """Add a process seen between snapshots (e.g. resolved on demand for a new socket)."""
        with self._lock:
            key = info.process_key
            if key in self._current or key in self._exited:
                return
            previous_key = self._current_by_pid.get(info.pid)
            if previous_key is not None:
                # The PID now belongs to a newer instance; the old one has exited.
                self._exited[previous_key] = (self._current.pop(previous_key), self._clock())
            self._current[key] = info
            self._current_by_pid[info.pid] = key

    def set_enrichment(
        self,
        process_key: str,
        sha256: str | None,
        signature: SignatureInfo | None,
        issues: dict[str, FieldIssue] | None = None,
    ) -> None:
        with self._lock:
            self._enrichment[process_key] = _Enrichment(sha256, signature, dict(issues or {}))

    def process(self, process_key: str) -> ProcessInfo | None:
        """A running or recently exited process instance, with enrichment merged."""
        with self._lock:
            info = self._current.get(process_key)
            if info is None and process_key in self._exited:
                info = self._exited[process_key][0]
            return None if info is None else self._merged(info)

    def process_by_pid(self, pid: int) -> ProcessInfo | None:
        """The *currently running* instance holding ``pid``."""
        with self._lock:
            key = self._current_by_pid.get(pid)
            return None if key is None else self._merged(self._current[key])

    def candidates_for_pid(self, pid: int) -> list[ProcessInfo]:
        """Running and recently exited instances that held ``pid`` (for correlation)."""
        with self._lock:
            found = [self._merged(p) for p in self._current.values() if p.pid == pid]
            found.extend(self._merged(p) for p, _ in self._exited.values() if p.pid == pid)
            return found

    def is_running(self, process_key: str) -> bool:
        with self._lock:
            return process_key in self._current

    def exited_at(self, process_key: str) -> datetime | None:
        with self._lock:
            entry = self._exited.get(process_key)
            return None if entry is None else entry[1]

    def parent_of(self, process: ProcessInfo) -> ProcessInfo | None:
        if process.ppid is None:
            return None
        return select_parent(process, self.candidates_for_pid(process.ppid))

    def ancestors(self, process: ProcessInfo, limit: int = 16) -> list[ProcessInfo]:
        chain: list[ProcessInfo] = []
        seen = {process.process_key}
        current = process
        while len(chain) < limit:
            parent = self.parent_of(current)
            if parent is None or parent.process_key in seen:
                break
            chain.append(parent)
            seen.add(parent.process_key)
            current = parent
        return chain

    def processes(self) -> list[ProcessInfo]:
        with self._lock:
            return [self._merged(p) for p in self._current.values()]

    def _merged(self, info: ProcessInfo) -> ProcessInfo:
        enrichment = self._enrichment.get(info.process_key)
        if enrichment is None:
            return info
        return info.model_copy(
            update={
                "sha256": enrichment.sha256,
                "signature": enrichment.signature,
                "unavailable": {**info.unavailable, **enrichment.issues},
            }
        )

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._retention
        expired = [key for key, (_, exited_at) in self._exited.items() if exited_at < cutoff]
        for key in expired:
            del self._exited[key]
        live = self._current.keys() | self._exited.keys()
        for key in self._enrichment.keys() - live:
            del self._enrichment[key]
        for key in self._history.keys() - live:
            del self._history[key]

    # -- network ----------------------------------------------------------------------------

    def apply_connections(self, items: Sequence[CorrelatedConnection]) -> None:
        with self._lock:
            self._connections = tuple(items)

    def connections(self) -> tuple[CorrelatedConnection, ...]:
        with self._lock:
            return self._connections

    def connections_of(self, process_key: str) -> list[CorrelatedConnection]:
        with self._lock:
            return [c for c in self._connections if c.process_key == process_key]

    # -- event history ----------------------------------------------------------------------

    def record_event(self, event: SecurityEvent) -> None:
        if event.process_key is None:
            return
        with self._lock:
            history = self._history.get(event.process_key)
            if history is None:
                history = deque(maxlen=self._history_size)
                self._history[event.process_key] = history
            history.append(event)

    def events_for(self, process_key: str, within: timedelta | None = None) -> list[SecurityEvent]:
        with self._lock:
            events = list(self._history.get(process_key, ()))
        if within is None:
            return events
        cutoff = self._clock() - within
        return [e for e in events if e.timestamp >= cutoff]

    # -- observability ----------------------------------------------------------------------

    def counts(self) -> StateCounts:
        with self._lock:
            return StateCounts(
                processes=len(self._current),
                exited_retained=len(self._exited),
                connections=len(self._connections),
                enriched=len(self._enrichment),
            )
