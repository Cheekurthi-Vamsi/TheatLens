"""Persistence monitor: diff successive persistence snapshots into ADDED/REMOVED/CHANGED events.

Runs on a slow cadence (persistence changes rarely). The first poll is an inventory
(``PERSISTENCE_DISCOVERED``) of what already exists — *not* "added", since these entries predate
monitoring. Only genuinely new entries afterwards are ``PERSISTENCE_ADDED`` — which is what a
newly installed autostart looks like, and what the PERSIST rules react to.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from winsentinel.collectors.persistence_collector import PersistenceCollector
from winsentinel.core.models import EventType, SecurityEvent
from winsentinel.core.models.persistence import PersistenceItem, PersistenceSnapshot

SOURCE: Final = "persistence_monitor"


def _data(item: PersistenceItem) -> dict[str, Any]:
    return {
        "kind": item.kind.value,
        "location": item.location,
        "name": item.name,
        "command": item.command,
        "executable": item.executable,
        "arguments": item.arguments,
        "enabled": item.enabled,
        "item_key": item.item_key,
    }


def _event(item: PersistenceItem, event_type: EventType, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type, timestamp=timestamp, source=SOURCE, data=_data(item)
    )


def diff_persistence(
    previous: PersistenceSnapshot | None, current: PersistenceSnapshot
) -> list[SecurityEvent]:
    if previous is None:
        return [
            _event(item, EventType.PERSISTENCE_DISCOVERED, current.timestamp)
            for item in sorted(current.items, key=lambda i: i.item_key)
        ]
    before = previous.by_key()
    after = current.by_key()
    events: list[SecurityEvent] = [
        _event(after[key], EventType.PERSISTENCE_ADDED, current.timestamp)
        for key in sorted(after.keys() - before.keys())
    ]
    events.extend(
        _event(before[key], EventType.PERSISTENCE_REMOVED, current.timestamp)
        for key in sorted(before.keys() - after.keys())
    )
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        if old.command != new.command or old.enabled != new.enabled:
            event = _event(new, EventType.PERSISTENCE_CHANGED, current.timestamp)
            events.append(
                event.model_copy(update={"data": {**event.data, "previous_command": old.command}})
            )
    return events


class PersistenceMonitor:
    name: Final = "persistence_monitor"

    def __init__(self, collector: PersistenceCollector, *, emit_inventory: bool = False) -> None:
        self._collector = collector
        self._emit_inventory = emit_inventory
        self._previous: PersistenceSnapshot | None = None

    def poll(self) -> list[SecurityEvent]:
        current = self._collector.collect()
        if self._previous is None:
            events = diff_persistence(None, current) if self._emit_inventory else []
        else:
            events = diff_persistence(self._previous, current)
        self._previous = current
        return events

    @property
    def last_snapshot(self) -> PersistenceSnapshot | None:
        return self._previous
