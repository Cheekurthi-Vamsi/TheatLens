"""Helpers for detection-rule tests: a small hand-built host and event factories."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from fixtures.fakes import BASE_TIME, connection, minutes, process
from winsentinel.core.models import (
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    Direction,
    EventType,
    NetworkConnection,
    ProcessInfo,
    ProcessSnapshot,
    SecurityEvent,
    SignatureInfo,
    SignatureSource,
    SignatureStatus,
    TransportProtocol,
)
from winsentinel.core.state import SystemState
from winsentinel.correlation.process_network import connection_record
from winsentinel.detection.paths import PathClassifier, PathContext
from winsentinel.detection.settings import DetectionSettings

NOW = minutes(10)

CONTEXT = PathContext(
    system_root=r"c:\windows",
    program_files=(r"c:\program files", r"c:\program files (x86)"),
    temp_dirs=(),
    trusted_paths=(r"c:\windows\system32", r"c:\program files", r"c:\program files (x86)"),
)


def settings(**overrides: Any) -> DetectionSettings:
    values: dict[str, Any] = {
        "paths": PathClassifier(CONTEXT),
        "correlation_window": timedelta(seconds=10),
        "burst_window": timedelta(seconds=60),
        "burst_threshold": 6,
        "fanout_threshold": 4,
        "failed_connection_threshold": 3,
        "common_remote_ports": frozenset({80, 443}),
    }
    values.update(overrides)
    return DetectionSettings(**values)


VALID = SignatureInfo(
    status=SignatureStatus.VALID, source=SignatureSource.EMBEDDED, signer="Contoso"
)
UNSIGNED = SignatureInfo(status=SignatureStatus.UNSIGNED)


def proc(
    pid: int,
    name: str,
    exe: str | None = None,
    *,
    ppid: int | None = 4,
    created: datetime | None = None,
    cmdline: Sequence[str] | None = None,
    **overrides: Any,
) -> ProcessInfo:
    values: dict[str, Any] = {
        "exe": exe if exe is not None else rf"C:\Users\alice\AppData\Local\Temp\{name}",
        "cmdline": tuple(cmdline) if cmdline is not None else None,
    }
    values.update(overrides)
    return process(pid, ppid=ppid, name=name, created=created or minutes(9), **values)


def host(
    processes: Sequence[ProcessInfo],
    *,
    connections: Sequence[CorrelatedConnection] = (),
    enrichment: dict[str, SignatureInfo | None] | None = None,
) -> SystemState:
    """State with ``processes`` running. ``enrichment`` maps process_key → signature (None =
    enrichment done without signature)."""
    state = SystemState(clock=lambda: NOW)
    state.apply_process_snapshot(ProcessSnapshot(timestamp=NOW, processes=tuple(processes)))
    for key, signature in (enrichment or {}).items():
        state.set_enrichment(key, "ef" * 32, signature)
    state.apply_connections(connections)
    return state


def appeared(p: ProcessInfo, event_type: EventType = EventType.PROCESS_STARTED) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        source="test",
        timestamp=NOW,
        process_key=p.process_key,
        pid=p.pid,
        data={"name": p.name, "exe": p.exe},
    )


def enriched(p: ProcessInfo) -> SecurityEvent:
    return appeared(p, EventType.PROCESS_ENRICHED)


def owned(
    p: ProcessInfo,
    remote: str | None = "93.184.216.34",
    remote_port: int | None = 443,
    *,
    created: datetime | None = None,
    local: str = "10.0.0.5",
    local_port: int = 50000,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    direction: Direction = Direction.OUTBOUND,
    protocol: TransportProtocol = TransportProtocol.TCP,
) -> CorrelatedConnection:
    conn: NetworkConnection = connection(
        p.pid,
        remote,
        remote_port,
        local=local,
        local_port=local_port,
        state=state,
        direction=direction,
        protocol=protocol,
        created=created or (p.create_time or BASE_TIME) + timedelta(seconds=2),
    )
    return CorrelatedConnection(
        connection=conn,
        attribution=Attribution.ATTRIBUTED,
        process_key=p.process_key,
        process_name=p.name,
        exe=p.exe,
    )


def socket_event(
    item: CorrelatedConnection,
    event_type: EventType = EventType.CONNECTION_OPENED,
    at: datetime = NOW,
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        source="test",
        timestamp=at,
        process_key=item.process_key,
        pid=item.pid,
        data=connection_record(item),
    )
