"""Process monitor: snapshot diffing into process lifecycle events.

The differ is a pure function over two snapshots, so every edge case (PID reuse, first
snapshot, suspended toggles) is unit-testable without Windows.

Identity is ``process_key`` (PID + creation time), never PID alone: if PID 4832 exits and a new
process receives PID 4832 between two polls, that is correctly reported as one STOPPED and one
STARTED event, not as "nothing changed".

Event semantics:
    * ``PROCESS_DISCOVERED`` — already running when monitoring began (the first snapshot). This is
      deliberately *not* "started": nothing is claimed about when it started relative to now.
    * ``PROCESS_STARTED`` — first observed at ``current.timestamp``; the true creation time is in
      ``data["create_time"]``.
    * ``PROCESS_STOPPED`` — exited somewhere in ``(previous.timestamp, current.timestamp]``; both
      bounds are recorded rather than inventing a precise exit time.
    * ``PROCESS_CHANGED`` — suspended state toggled.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from threatlens.collectors.process_collector import ProcessCollector
from threatlens.core.models import EventType, ProcessInfo, ProcessSnapshot, SecurityEvent
from threatlens.correlation.process_tree import verified_parent

SOURCE: Final = "process_monitor"


def _iso(ts: datetime | None) -> str | None:
    return None if ts is None else ts.isoformat()


def _order(process: ProcessInfo) -> tuple[float, int]:
    return (process.create_time.timestamp() if process.create_time else 0.0, process.pid)


def process_event_data(process: ProcessInfo, parent: ProcessInfo | None) -> dict[str, Any]:
    return {
        "name": process.name,
        "ppid": process.ppid,
        "parent_key": parent.process_key if parent else None,
        "parent_name": parent.name if parent else None,
        "exe": process.exe,
        "cmdline": list(process.cmdline) if process.cmdline is not None else None,
        "username": process.username,
        "integrity_level": process.integrity_level.value,
        "session_id": process.session_id,
        "create_time": _iso(process.create_time),
    }


def _lifecycle_event(
    event_type: EventType,
    process: ProcessInfo,
    snapshot: ProcessSnapshot,
    by_pid: dict[int, ProcessInfo],
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        timestamp=snapshot.timestamp,
        source=SOURCE,
        process_key=process.process_key,
        pid=process.pid,
        data=process_event_data(process, verified_parent(process, by_pid)),
    )


def _stopped_event(
    process: ProcessInfo, previous: ProcessSnapshot, current: ProcessSnapshot
) -> SecurityEvent:
    lifetime = (
        None
        if process.create_time is None
        else round((current.timestamp - process.create_time).total_seconds(), 3)
    )
    return SecurityEvent(
        event_type=EventType.PROCESS_STOPPED,
        timestamp=current.timestamp,
        source=SOURCE,
        process_key=process.process_key,
        pid=process.pid,
        data={
            "name": process.name,
            "exe": process.exe,
            "exited_after": _iso(previous.timestamp),
            "exited_before": _iso(current.timestamp),
            "max_lifetime_seconds": lifetime,
        },
    )


def inventory_events(snapshot: ProcessSnapshot) -> list[SecurityEvent]:
    """``PROCESS_DISCOVERED`` for every process in the first snapshot, parents first."""
    by_pid = snapshot.by_pid()
    return [
        _lifecycle_event(EventType.PROCESS_DISCOVERED, process, snapshot, by_pid)
        for process in sorted(snapshot.processes, key=_order)
    ]


def diff_snapshots(
    previous: ProcessSnapshot | None, current: ProcessSnapshot
) -> list[SecurityEvent]:
    """Return change events between two snapshots.

    The first snapshot (``previous is None``) yields no change events; use
    :func:`inventory_events` for it. Started events are ordered by creation time so parents
    precede children.
    """
    if previous is None:
        return []
    before = previous.by_key()
    after = current.by_key()
    by_pid = current.by_pid()

    events: list[SecurityEvent] = [
        _lifecycle_event(EventType.PROCESS_STARTED, process, current, by_pid)
        for process in sorted((after[k] for k in after.keys() - before.keys()), key=_order)
    ]
    events.extend(
        _stopped_event(process, previous, current)
        for process in sorted((before[k] for k in before.keys() - after.keys()), key=_order)
    )
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        if (
            old.suspended is not None
            and new.suspended is not None
            and old.suspended != new.suspended
        ):
            events.append(
                SecurityEvent(
                    event_type=EventType.PROCESS_CHANGED,
                    timestamp=current.timestamp,
                    source=SOURCE,
                    process_key=key,
                    pid=new.pid,
                    data={
                        "name": new.name,
                        "changed": {"suspended": [old.suspended, new.suspended]},
                    },
                )
            )
    return events


class ProcessMonitor:
    """Holds the previous snapshot and produces events on each poll."""

    name: Final = "process_monitor"

    def __init__(self, collector: ProcessCollector, *, emit_inventory: bool = False) -> None:
        self._collector = collector
        self._emit_inventory = emit_inventory
        self._previous: ProcessSnapshot | None = None

    @property
    def last_snapshot(self) -> ProcessSnapshot | None:
        return self._previous

    def poll_snapshot(self) -> tuple[ProcessSnapshot, list[SecurityEvent]]:
        current = self._collector.collect()
        if self._previous is None:
            events = inventory_events(current) if self._emit_inventory else []
        else:
            events = diff_snapshots(self._previous, current)
        self._previous = current
        return current, events

    def poll(self) -> list[SecurityEvent]:
        return self.poll_snapshot()[1]
