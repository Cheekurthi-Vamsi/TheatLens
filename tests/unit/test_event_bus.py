from __future__ import annotations

import threading
import time

from threatlens.core.event_bus import EventBus
from threatlens.core.models import EventType, SecurityEvent


def event(event_type: EventType = EventType.PROCESS_STARTED, pid: int = 1) -> SecurityEvent:
    return SecurityEvent(event_type=event_type, source="test", pid=pid)


def test_type_filtered_subscriptions() -> None:
    bus = EventBus()
    processes: list[SecurityEvent] = []
    everything: list[SecurityEvent] = []
    bus.subscribe("processes", processes.append, {EventType.PROCESS_STARTED})
    bus.subscribe("all", everything.append)
    bus.publish(event(EventType.PROCESS_STARTED))
    bus.publish(event(EventType.CONNECTION_OPENED))
    assert bus.dispatch_pending() == 2
    assert [e.event_type for e in processes] == [EventType.PROCESS_STARTED]
    assert len(everything) == 2


def test_failing_handler_is_isolated_and_counted() -> None:
    bus = EventBus()
    received: list[SecurityEvent] = []

    def broken(_: SecurityEvent) -> None:
        raise RuntimeError("handler bug")

    bus.subscribe("broken", broken)
    bus.subscribe("healthy", received.append)
    for pid in range(3):
        bus.publish(event(pid=pid))
    bus.dispatch_pending()
    assert len(received) == 3
    stats = bus.stats()
    assert stats.handler_errors == 3 and stats.dispatched == 3


def test_bounded_queue_drops_oldest_and_counts() -> None:
    bus = EventBus(capacity=3)
    received: list[int | None] = []
    bus.subscribe("collect", lambda e: received.append(e.pid))
    for pid in range(5):
        assert bus.publish(event(pid=pid)) is True
    assert bus.stats().dropped == 2
    bus.dispatch_pending()
    assert received == [2, 3, 4]  # newest information survives


def test_threaded_dispatch_and_graceful_drain() -> None:
    bus = EventBus()
    received: list[int | None] = []
    done = threading.Event()

    def slow(e: SecurityEvent) -> None:
        time.sleep(0.001)
        received.append(e.pid)
        if e.pid == 199:
            done.set()

    bus.subscribe("slow", slow)
    bus.start()
    for pid in range(200):
        bus.publish(event(pid=pid))
    assert bus.stop(timeout=5.0) is True  # drained everything already queued
    assert received == list(range(200))
    assert bus.publish(event()) is False  # no longer accepting
