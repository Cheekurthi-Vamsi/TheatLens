"""The monitoring engine: wires collectors, monitors, state, enrichment and the event bus.

Runtime structure (docs/architecture.md §5.4)::

    thread: process_monitor ──┐                           ┌── state history
    thread: network_monitor ──┼─▶ state + EventBus ─▶ dispatcher ┼── enrichment requests
    thread: status_writer ────┘       (bounded)                 └── subscribers (CLI stream, rules…)
    thread: enrichment ─────────▶ state + PROCESS_ENRICHED
    thread: watchdog ───────────▶ TIMED_OUT transitions

Failure isolation:
    * Each monitor runs on its own thread with its own health, backoff and timeout. If the
      network collector fails, process monitoring, enrichment and dispatch continue, and a
      ``COLLECTOR_STATUS`` event tells subscribers exactly what degraded.
    * Handlers are isolated by the bus; enrichment errors are counted by the worker.

Graceful shutdown order: stop monitors → stop enrichment → drain bus → write final status.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from winsentinel import __version__
from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.collectors.persistence_collector import PersistenceCollector
from winsentinel.collectors.process_collector import (
    ProcessCollector,
    ProcessCollectorOptions,
    ProcessEnricher,
)
from winsentinel.config import Config
from winsentinel.core.enrichment import EnrichmentWorker
from winsentinel.core.event_bus import EventBus, Handler
from winsentinel.core.models import (
    ComponentHealth,
    ComponentStatus,
    EngineState,
    EngineStats,
    EngineStatus,
    EventType,
    ProcessInfo,
    SecurityEvent,
)
from winsentinel.core.scheduler import PeriodicTask, Scheduler, TaskRunner
from winsentinel.core.state import SystemState
from winsentinel.core.status_file import StatusFile
from winsentinel.errors import CollectorUnavailableError, ProcessNotFoundError
from winsentinel.monitors.file_monitor import FileMonitor
from winsentinel.monitors.network_monitor import NetworkMonitor
from winsentinel.monitors.persistence_monitor import PersistenceMonitor
from winsentinel.monitors.process_monitor import ProcessMonitor
from winsentinel.security.hashing import FileHasher
from winsentinel.security.signatures import SignatureVerifier
from winsentinel.storage.writer import DatabaseWriter
from winsentinel.utils.time import utc_now

logger = logging.getLogger(__name__)

SOURCE: Final = "engine"
BYTES_PER_MB: Final = 1024 * 1024
STATUS_WRITER_TIMEOUT_SECONDS: Final = 10.0
UNRESOLVABLE_PID_TTL_SECONDS: Final = 30.0
_SPECIAL_PIDS: Final = frozenset({0, 4})


@dataclass(frozen=True, slots=True)
class ShutdownReport:
    duration_seconds: float
    events_published: int
    events_dispatched: int
    events_dropped: int
    drained: bool
    stuck_components: tuple[str, ...]


class Engine:
    def __init__(
        self,
        config: Config,
        *,
        process_collector: ProcessCollector | None = None,
        network_collector: NetworkCollector | None = None,
        attribution_collector: ProcessCollector | None = None,
        enricher: ProcessEnricher | None = None,
        persistence_collector: PersistenceCollector | None = None,
        status_file: StatusFile | None = None,
        writer: DatabaseWriter | None = None,
        interval: float | None = None,
        emit_inventory: bool = True,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._config = config
        self._clock = clock
        self._interval = interval or config.general.refresh_interval_seconds
        self._status_file = status_file
        self._writer = writer
        self._engine_state = EngineState.STOPPED
        self._started_at = clock()
        self._started_mono = time.monotonic()
        self._rate_sample: tuple[float, int] | None = None
        self._unresolvable: dict[int, float] = {}
        self._rules_enabled = 0
        self._detection_count: Callable[[], int] = lambda: 0

        engine_config = config.engine
        self.state = SystemState(
            exit_retention=timedelta(seconds=engine_config.exit_retention_seconds), clock=clock
        )
        self.bus = EventBus(engine_config.event_queue_size)
        collector_options = ProcessCollectorOptions(
            redact_command_lines=config.process.redact_command_lines
        )
        self.enrichment = EnrichmentWorker(
            enricher
            or ProcessEnricher(
                FileHasher(max_file_size=config.process.hash_max_file_size_mb * BYTES_PER_MB),
                SignatureVerifier(),
                verify_signatures=config.process.verify_signatures,
            ),
            self.state,
            self.bus.publish,
            capacity=engine_config.enrichment_queue_size,
        )
        self.bus.subscribe("state-history", self.state.record_event)
        self.bus.subscribe(
            "enrichment-requests",
            self.enrichment.on_event,
            {EventType.PROCESS_STARTED, EventType.PROCESS_DISCOVERED},
        )
        if writer is not None:
            self.bus.subscribe("storage", writer.on_event)

        timeout = config.collectors.collector_timeout_seconds
        runners: list[TaskRunner] = []
        self._disabled: list[ComponentHealth] = []
        self._process_monitor: ProcessMonitor | None = None
        self._network_monitor: NetworkMonitor | None = None
        self._attribution_collector: ProcessCollector | None = None

        if config.collectors.enable_process:
            self._process_monitor = ProcessMonitor(
                process_collector or ProcessCollector(options=collector_options),
                emit_inventory=emit_inventory,
            )
            runners.append(
                self._runner("process_monitor", self._interval, self._poll_processes, timeout)
            )
        else:
            self._disabled.append(
                ComponentHealth(name="process_monitor", status=ComponentStatus.DISABLED)
            )

        if config.collectors.enable_network:
            self._attribution_collector = attribution_collector or ProcessCollector(
                options=collector_options
            )
            self._network_monitor = NetworkMonitor(
                network_collector or NetworkCollector(), self._lookup, emit_inventory=emit_inventory
            )
            runners.append(
                self._runner("network_monitor", self._interval, self._poll_network, timeout)
            )
        else:
            self._disabled.append(
                ComponentHealth(name="network_monitor", status=ComponentStatus.DISABLED)
            )

        self._file_monitor: FileMonitor | None = None
        if config.collectors.enable_file_monitor:
            paths = [Path(p) for p in config.file_monitor.monitored_paths] or None
            self._file_monitor = FileMonitor(self.bus.publish, paths)
        else:
            self._disabled.append(
                ComponentHealth(name="file_monitor", status=ComponentStatus.DISABLED)
            )

        self._persistence_monitor: PersistenceMonitor | None = None
        if config.collectors.enable_persistence_monitor:
            self._persistence_monitor = PersistenceMonitor(
                persistence_collector or PersistenceCollector(), emit_inventory=emit_inventory
            )
            runners.append(
                self._runner(
                    "persistence_monitor",
                    engine_config.persistence_interval_seconds,
                    self._poll_persistence,
                    max(timeout, 30.0),
                )
            )
        else:
            self._disabled.append(
                ComponentHealth(name="persistence_monitor", status=ComponentStatus.DISABLED)
            )

        if status_file is not None:
            runners.append(
                self._runner(
                    "status_writer",
                    engine_config.status_interval_seconds,
                    self._write_status,
                    STATUS_WRITER_TIMEOUT_SECONDS,
                )
            )
        self._runners = {runner.name: runner for runner in runners}
        self.scheduler = Scheduler(runners)

    # -- composition hooks ------------------------------------------------------------------

    def subscribe(
        self, name: str, handler: Handler, event_types: Collection[EventType] | None = None
    ) -> None:
        self.bus.subscribe(name, handler, event_types)

    def set_detection_stats(
        self, *, rules_enabled: int, detection_count: Callable[[], int]
    ) -> None:
        self._rules_enabled = rules_enabled
        self._detection_count = detection_count

    @property
    def interval(self) -> float:
        return self._interval

    @property
    def engine_state(self) -> EngineState:
        return self._engine_state

    # -- lifecycle --------------------------------------------------------------------------

    def start(self) -> None:
        """Start dispatching, run the first collection synchronously, then start threads."""
        if self._engine_state is not EngineState.STOPPED:
            raise RuntimeError("Engine already started")
        self._engine_state = EngineState.STARTING
        self._started_at = self._clock()
        self._started_mono = time.monotonic()
        if self._writer is not None:
            self._writer.start()
        self.bus.start()
        self.enrichment.start()
        if self._file_monitor is not None:
            self._file_monitor.start()
        # Processes before sockets, so every inventory socket's owner is already known.
        for name in ("process_monitor", "network_monitor"):
            if name in self._runners:
                self._runners[name].run_once()
        self._engine_state = EngineState.RUNNING
        self.scheduler.start(run_immediately=False)
        if self._status_file is not None:
            self._write_status_safely()

    def stop(self, timeout: float | None = None) -> ShutdownReport:
        budget = timeout if timeout is not None else self._config.engine.shutdown_timeout_seconds
        self._engine_state = EngineState.STOPPING
        stuck = self.scheduler.stop(budget * 0.3)
        if self._file_monitor is not None:
            self._file_monitor.stop(budget * 0.2)
        self.enrichment.stop(budget * 0.2)
        drained = self.bus.stop(budget * 0.3)  # dispatches remaining events into the writer queue
        if self._writer is not None:
            self._writer.stop(budget * 0.2)  # then the writer drains, checkpoints and closes
        self._engine_state = EngineState.STOPPED
        if self._status_file is not None:
            self._write_status_safely()
        stats = self.bus.stats()
        return ShutdownReport(
            duration_seconds=round(time.monotonic() - self._started_mono, 3),
            events_published=stats.published,
            events_dispatched=stats.dispatched,
            events_dropped=stats.dropped,
            drained=drained,
            stuck_components=tuple(stuck),
        )

    def run_cycle(self) -> None:
        """One synchronous collect → dispatch → enrich → dispatch pass (tests; not started)."""
        for runner in self._runners.values():
            if runner.name != "status_writer":
                runner.run_once()
        self.bus.dispatch_pending()
        self.enrichment.process_pending()
        self.bus.dispatch_pending()

    # -- tasks ------------------------------------------------------------------------------

    def _runner(
        self, name: str, interval: float, run: Callable[[], None], timeout: float
    ) -> TaskRunner:
        return TaskRunner(
            PeriodicTask(name=name, interval=interval, run=run, timeout=timeout),
            max_backoff=self._config.engine.max_backoff_seconds,
            clock=self._clock,
            on_transition=self._on_transition,
        )

    def _poll_processes(self) -> None:
        if self._process_monitor is None:
            return
        snapshot, events = self._process_monitor.poll_snapshot()
        self.state.apply_process_snapshot(snapshot)
        for event in events:
            self.bus.publish(event)

    def _poll_network(self) -> None:
        if self._network_monitor is None:
            return
        _, items, events = self._network_monitor.poll()
        self.state.apply_connections(items)
        for event in events:
            self.bus.publish(event)

    def _poll_persistence(self) -> None:
        if self._persistence_monitor is None:
            return
        for event in self._persistence_monitor.poll():
            self.bus.publish(event)

    def _lookup(self, pid: int) -> list[ProcessInfo]:
        """Candidate owners for a socket's PID, resolving a not-yet-seen process on demand."""
        if pid not in _SPECIAL_PIDS and self.state.process_by_pid(pid) is None:
            resolved = self._resolve_pid(pid)
            if resolved is not None:
                self.state.observe_process(resolved)
        return self.state.candidates_for_pid(pid)

    def _resolve_pid(self, pid: int) -> ProcessInfo | None:
        now = time.monotonic()
        retry_at = self._unresolvable.get(pid)
        if self._attribution_collector is None or (retry_at is not None and now < retry_at):
            return None
        try:
            info = self._attribution_collector.collect_pid(pid)
        except (ProcessNotFoundError, CollectorUnavailableError):
            self._unresolvable[pid] = now + UNRESOLVABLE_PID_TTL_SECONDS
            if len(self._unresolvable) > 4096:
                self._unresolvable = {p: t for p, t in self._unresolvable.items() if t > now}
            return None
        self._unresolvable.pop(pid, None)
        return info

    def _on_transition(self, old: ComponentHealth, new: ComponentHealth) -> None:
        # Coming online normally and shutting down are not news; degradations and recoveries are.
        if new.status is ComponentStatus.STOPPED or (
            old.status is ComponentStatus.STARTING and new.status is ComponentStatus.OK
        ):
            return
        self.bus.publish(
            SecurityEvent(
                event_type=EventType.COLLECTOR_STATUS,
                timestamp=self._clock(),
                source=SOURCE,
                data={
                    "component": new.name,
                    "status": new.status.value,
                    "previous_status": old.status.value,
                    "last_error": new.last_error,
                    "detail": new.detail,
                },
            )
        )

    def _write_status(self) -> None:
        if self._status_file is not None:
            self._status_file.write(self.status())

    def _write_status_safely(self) -> None:
        try:
            self._write_status()
        except OSError as exc:
            logger.warning("event=STATUS_WRITE_FAILED error=%s", exc)

    # -- observability ----------------------------------------------------------------------

    def health(self) -> list[ComponentHealth]:
        components = [*self.scheduler.health(), self.enrichment.health()]
        if self._file_monitor is not None:
            components.append(self._file_monitor.health())
        if self._writer is not None:
            components.append(self._writer.health())
        return [*components, *self._disabled]

    def status(self) -> EngineStatus:
        bus = self.bus.stats()
        counts = self.state.counts()
        me = self.state.process_by_pid(os.getpid())
        return EngineStatus(
            version=__version__,
            pid=os.getpid(),
            process_key=me.process_key if me else None,
            state=self._engine_state,
            started_at=self._started_at,
            updated_at=self._clock(),
            interval_seconds=self._interval,
            components=tuple(self.health()),
            bus=bus,
            stats=EngineStats(
                processes=counts.processes,
                exited_retained=counts.exited_retained,
                connections=counts.connections,
                enriched=self.enrichment.enriched,
                detections=self._detection_count(),
                events_per_second=self._events_per_second(bus.dispatched),
            ),
            rules_enabled=self._rules_enabled,
            engine_cpu_percent=me.cpu_percent if me else None,
            engine_working_set=me.working_set if me else None,
        )

    def _events_per_second(self, dispatched: int) -> float | None:
        now = time.monotonic()
        previous = self._rate_sample
        self._rate_sample = (now, dispatched)
        if previous is None or now - previous[0] < 0.5:
            return None
        return round((dispatched - previous[1]) / (now - previous[0]), 2)
