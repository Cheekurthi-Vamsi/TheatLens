"""One-shot evaluation of a single process, used by ``winsentinel inspect``.

It builds a throwaway :class:`SystemState` from a snapshot and replays the *inventory* view of the
target (discovered process, its enrichment, its sockets) through a fresh detection engine.

What this can and cannot find:
    * Static and timestamp-based rules work fully: location, signature, name, lineage, command
      line, and "connected N seconds after start" (kernel timestamps).
    * Rules that need to *watch change over time* (a listener opening, first-seen communication,
      connection bursts) cannot fire from a single snapshot; run ``winsentinel monitor`` for those.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from winsentinel.core.models import (
    CorrelatedConnection,
    DetectionResult,
    EventType,
    FieldIssue,
    ProcessInfo,
    ProcessSnapshot,
    SecurityEvent,
)
from winsentinel.core.state import SystemState
from winsentinel.correlation.process_network import connection_record
from winsentinel.detection.engine import DetectionEngine
from winsentinel.detection.rules import build_rules
from winsentinel.detection.settings import DetectionSettings

SOURCE = "inspect"


def scan_process(
    target: ProcessInfo,
    processes: Sequence[ProcessInfo],
    connections: Sequence[CorrelatedConnection],
    settings: DetectionSettings,
    *,
    now: datetime,
) -> list[DetectionResult]:
    state = SystemState(clock=lambda: now)
    state.apply_process_snapshot(ProcessSnapshot(timestamp=now, processes=tuple(processes)))
    issues: dict[str, FieldIssue] = {k: v for k, v in target.unavailable.items() if k == "sha256"}
    if target.sha256 is not None or target.signature is not None or issues:
        state.set_enrichment(target.process_key, target.sha256, target.signature, issues)
    state.apply_connections(connections)
    engine = DetectionEngine(
        build_rules(settings),
        state,
        disabled_rules=settings.disabled_rules,
        ignored_executables=settings.ignored_executables,
    )

    def event(event_type: EventType, data: dict[str, object]) -> SecurityEvent:
        return SecurityEvent(
            event_type=event_type,
            timestamp=now,
            source=SOURCE,
            process_key=target.process_key,
            pid=target.pid,
            data=data,
        )

    replay = [
        event(EventType.PROCESS_DISCOVERED, {"name": target.name, "exe": target.exe}),
        event(EventType.PROCESS_ENRICHED, {"name": target.name, "exe": target.exe}),
    ]
    for socket in connections:
        if socket.process_key != target.process_key:
            continue
        kind = (
            EventType.LISTENER_DISCOVERED
            if socket.connection.is_listener
            else EventType.CONNECTION_DISCOVERED
        )
        replay.append(event(kind, connection_record(socket)))

    results: list[DetectionResult] = []
    for replayed in replay:
        results.extend(engine.handle(replayed))
    return results
