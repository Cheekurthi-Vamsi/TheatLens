"""Process ↔ network correlation (Phase 3).

The socket tables give an owning **PID**. A PID is not an identity (Windows reuses PIDs), so a
naive join can attribute a socket to the wrong program: process A opens a socket and exits, the
socket lingers in ``TIME_WAIT``/``CLOSE_WAIT``, and process B receives A's PID.

WinSentinel joins on **PID + time**. Each socket carries its kernel creation timestamp; the owner
is the most recent process instance with that PID that was created *before* the socket. If every
process with that PID is newer than the socket, the join is refused and the socket is marked
``PID_REUSE_SUSPECTED`` rather than blamed on an innocent process.

Other cases:
    * PID 0 → ``UNATTRIBUTED`` (the owner already released the socket).
    * PID 4 → ``KERNEL``: kernel-mode sockets (SMB, ``http.sys`` for IIS/WinRM/WSD). The user-mode
      application that registered an ``http.sys`` URL is not visible here.
    * PID not found among known processes → ``UNATTRIBUTED``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final

from winsentinel.core.models import (
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    NetworkConnection,
    ProcessInfo,
)
from winsentinel.correlation.process_tree import ancestry

IDLE_PID: Final = 0
SYSTEM_PID: Final = 4
# Both timestamps come from the same kernel clock; the tolerance only absorbs rounding to ms.
CREATION_TOLERANCE: Final = timedelta(seconds=1)

CandidateLookup = Callable[[int], Sequence[ProcessInfo]]


def attribute(
    connection: NetworkConnection, candidates: Sequence[ProcessInfo]
) -> tuple[Attribution, ProcessInfo | None]:
    """Decide which process instance owns ``connection``. Pure function.

    ``candidates`` are all known process instances (running or recently exited) with the
    connection's PID.
    """
    if connection.pid == IDLE_PID:
        return Attribution.UNATTRIBUTED, None
    if connection.pid == SYSTEM_PID:
        system = next(iter(candidates), None)
        return Attribution.KERNEL, system
    if not candidates:
        return Attribution.UNATTRIBUTED, None

    def created(p: ProcessInfo) -> float:
        return p.create_time.timestamp() if p.create_time else 0.0

    if connection.created_at is None:
        return Attribution.ATTRIBUTED, max(candidates, key=created)

    eligible = [
        p
        for p in candidates
        if p.create_time is None or p.create_time <= connection.created_at + CREATION_TOLERANCE
    ]
    if not eligible:
        return Attribution.PID_REUSE_SUSPECTED, None
    return Attribution.ATTRIBUTED, max(eligible, key=created)


def correlate(
    connections: Iterable[NetworkConnection], lookup: CandidateLookup
) -> list[CorrelatedConnection]:
    """Attribute every connection using ``lookup(pid) -> candidates``."""
    result: list[CorrelatedConnection] = []
    for connection in connections:
        attribution, owner = attribute(connection, lookup(connection.pid))
        result.append(
            CorrelatedConnection(
                connection=connection,
                attribution=attribution,
                process_key=owner.process_key if owner else None,
                process_name=owner.name if owner else None,
                exe=owner.exe if owner else None,
            )
        )
    return result


def lookup_from_processes(processes: Iterable[ProcessInfo]) -> CandidateLookup:
    """Build a candidate lookup from a flat list of process instances."""
    index: dict[int, list[ProcessInfo]] = {}
    for process in processes:
        index.setdefault(process.pid, []).append(process)
    return lambda pid: index.get(pid, [])


def connection_record(item: CorrelatedConnection) -> dict[str, Any]:
    """Flat, stable dictionary for one socket — the JSON output shape and event payload."""
    c = item.connection
    return {
        "pid": c.pid,
        "process": item.process_name,
        "process_key": item.process_key,
        "exe": item.exe,
        "attribution": item.attribution.value,
        "protocol": c.protocol.value,
        "family": c.family.value,
        "local_address": c.local_address,
        "local_port": c.local_port,
        "remote_address": c.remote_address,
        "remote_port": c.remote_port,
        "state": c.state.value,
        "direction": c.direction.value,
        "local_scope": c.local_scope.value,
        "remote_scope": c.remote_scope.value if c.remote_scope else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "owner_module": c.owner_module,
        "connection_key": c.connection_key,
    }


@dataclass(slots=True)
class ProcessConnections:
    """One process and the sockets attributed to it."""

    process: ProcessInfo | None
    pid: int
    attribution: Attribution
    connections: list[CorrelatedConnection] = field(default_factory=list)


ACTIVE_EXCLUDED_STATES: Final = frozenset({ConnectionState.LISTEN, ConnectionState.NONE})


def group_by_process(
    items: Iterable[CorrelatedConnection], processes_by_key: dict[str, ProcessInfo]
) -> list[ProcessConnections]:
    """Group correlated sockets by owning process instance (unattributed ones grouped by PID)."""
    groups: dict[str, ProcessConnections] = {}
    for item in items:
        group_key = item.process_key or f"{item.attribution.value}:{item.pid}"
        group = groups.get(group_key)
        if group is None:
            group = ProcessConnections(
                process=processes_by_key.get(item.process_key) if item.process_key else None,
                pid=item.pid,
                attribution=item.attribution,
            )
            groups[group_key] = group
        group.connections.append(item)
    return sorted(
        groups.values(),
        key=lambda g: ((g.process.name.lower() if g.process else "~"), g.pid),
    )


@dataclass(frozen=True, slots=True)
class ConnectionChain:
    """connection → owning process → verified ancestry (nearest first)."""

    connection: CorrelatedConnection
    process: ProcessInfo | None
    ancestors: tuple[ProcessInfo, ...]


def connection_chain(
    item: CorrelatedConnection, processes: Sequence[ProcessInfo]
) -> ConnectionChain:
    by_key = {p.process_key: p for p in processes}
    by_pid = {p.pid: p for p in processes}
    owner = by_key.get(item.process_key) if item.process_key else None
    parents = tuple(ancestry(owner, by_pid)) if owner else ()
    return ConnectionChain(connection=item, process=owner, ancestors=parents)
