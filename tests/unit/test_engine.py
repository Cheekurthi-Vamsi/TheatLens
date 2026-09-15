"""Engine behaviour with fake collectors — including the Phase 4 exit criterion: the engine
survives an injected failing collector."""

from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from fixtures.fakes import (
    FakeClock,
    FakeEnricher,
    FakeInspector,
    FakeSocketSource,
    FakeSource,
    entry,
    minutes,
    socket_entry,
)
from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.collectors.process_collector import ProcessCollector
from winsentinel.config import Config
from winsentinel.core.engine import Engine
from winsentinel.core.models import ComponentStatus, EngineState, EventType, SecurityEvent
from winsentinel.core.status_file import StatusFile


def process_collector(source: FakeSource, clock: FakeClock) -> ProcessCollector:
    return ProcessCollector(
        source, FakeInspector(), clock=clock.now, monotonic=clock.monotonic, cpu_count=2
    )


def build_engine(
    process_source: FakeSource,
    socket_source: FakeSocketSource,
    *,
    attribution_source: FakeSource | None = None,
    status_file: StatusFile | None = None,
    interval: float | None = None,
) -> tuple[Engine, list[SecurityEvent]]:
    clock = FakeClock()
    engine = Engine(
        Config(),
        process_collector=process_collector(process_source, clock),
        network_collector=NetworkCollector(socket_source, clock=clock.now),
        attribution_collector=process_collector(attribution_source or process_source, clock),
        enricher=FakeEnricher(),  # type: ignore[arg-type]
        status_file=status_file,
        interval=interval,
        clock=clock.now,
    )
    received: list[SecurityEvent] = []
    engine.subscribe("test", received.append)
    return engine, received


def types(events: list[SecurityEvent]) -> list[EventType]:
    return [e.event_type for e in events]


def test_first_cycle_is_inventory_then_changes_are_events() -> None:
    first = [entry(4, ppid=0, name="System"), entry(100, name="app.exe")]
    second = [*first, entry(200, ppid=100, name="new.exe", created=minutes(4))]
    sockets_first = [socket_entry(100, "0.0.0.0", 8080, state="LISTEN")]
    sockets_second = [*sockets_first, socket_entry(200, local_port=50001, created=minutes(4.5))]
    engine, received = build_engine(
        FakeSource(first, second), FakeSocketSource(sockets_first, sockets_second)
    )

    engine.run_cycle()
    assert EventType.PROCESS_DISCOVERED in types(received)
    assert EventType.LISTENER_DISCOVERED in types(received)
    assert EventType.PROCESS_STARTED not in types(received)
    assert EventType.PROCESS_ENRICHED in types(received)  # enrichment ran for inventory

    received.clear()
    engine.run_cycle()
    started = [e for e in received if e.event_type is EventType.PROCESS_STARTED]
    opened = [e for e in received if e.event_type is EventType.CONNECTION_OPENED]
    assert [e.pid for e in started] == [200]
    assert opened and opened[0].data["process"] == "new.exe"
    assert engine.state.process_by_pid(200).sha256 == "ab" * 32  # type: ignore[union-attr]


def test_engine_survives_failing_process_collector() -> None:
    """Exit criterion: one collector failing must not stop the rest of the engine."""
    broken = FakeSource(error=OSError(5, "simulated enumeration failure"))
    attribution = FakeSource([entry(100, name="still-attributed.exe")])
    sockets = FakeSocketSource(
        [socket_entry(100, local_port=50000)],
        [socket_entry(100, local_port=50000), socket_entry(100, local_port=50001)],
    )
    engine, received = build_engine(broken, sockets, attribution_source=attribution)

    for _ in range(3):
        engine.run_cycle()

    health = {h.name: h for h in engine.health()}
    assert health["process_monitor"].status is ComponentStatus.UNAVAILABLE
    assert "simulated enumeration failure" in (health["process_monitor"].last_error or "")
    assert health["network_monitor"].status is ComponentStatus.OK
    assert health["enrichment"].status is ComponentStatus.OK

    statuses = [e.data["status"] for e in received if e.event_type is EventType.COLLECTOR_STATUS]
    assert statuses == ["DEGRADED", "UNAVAILABLE"]
    opened = [e for e in received if e.event_type is EventType.CONNECTION_OPENED]
    assert [e.data["local_port"] for e in opened] == [50001]
    # Sockets are still attributed, via on-demand resolution, while process polling is down.
    assert opened[0].data["process"] == "still-attributed.exe"


def test_socket_for_process_born_between_polls_is_attributed_on_demand() -> None:
    known = [entry(100, name="app.exe")]
    with_newcomer = [*known, entry(300, name="newcomer.exe", created=minutes(4.9))]
    engine, received = build_engine(
        FakeSource(known),
        FakeSocketSource([], [socket_entry(300, local_port=51000, created=minutes(4.95))]),
        attribution_source=FakeSource(with_newcomer),
    )
    engine.run_cycle()
    engine.run_cycle()
    (opened,) = [e for e in received if e.event_type is EventType.CONNECTION_OPENED]
    assert opened.data["process"] == "newcomer.exe"
    assert opened.data["attribution"] == "ATTRIBUTED"


def test_broken_subscriber_does_not_stop_event_flow() -> None:
    engine, received = build_engine(FakeSource([entry(100)]), FakeSocketSource([socket_entry(100)]))

    def broken(_: SecurityEvent) -> None:
        raise ValueError("subscriber bug")

    engine.subscribe("broken", broken)
    engine.run_cycle()
    assert received
    assert engine.bus.stats().handler_errors > 0


def test_threaded_start_stop_writes_status(tmp_path: Path) -> None:
    status_file = StatusFile(tmp_path / "engine-status.json")
    engine, received = build_engine(
        FakeSource([entry(100)]),
        FakeSocketSource([socket_entry(100)]),
        status_file=status_file,
        interval=0.5,
    )
    engine.start()
    running = status_file.read()
    assert running is not None and running.state is EngineState.RUNNING
    time.sleep(0.3)
    report = engine.stop(timeout=3.0)
    assert report.drained and report.stuck_components == ()
    assert report.events_dropped == 0
    final = status_file.read()
    assert final is not None and final.state is EngineState.STOPPED
    assert {c.name for c in final.components} >= {
        "process_monitor",
        "network_monitor",
        "enrichment",
    }
    assert EventType.PROCESS_DISCOVERED in types(received)


def test_disabled_collectors_are_reported() -> None:
    config = Config.model_validate({"collectors": {"enable_network": False}})
    engine = Engine(
        config,
        process_collector=process_collector(FakeSource([entry(1)]), FakeClock()),
        enricher=FakeEnricher(),  # type: ignore[arg-type]
    )
    statuses = {h.name: h.status for h in engine.health()}
    assert statuses["network_monitor"] is ComponentStatus.DISABLED
    assert timedelta(seconds=Config().engine.exit_retention_seconds) == timedelta(minutes=5)
