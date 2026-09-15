"""Network monitor: socket-table diffing into connection and listener events.

Identity is ``connection_key`` (endpoints + owning PID + kernel socket creation time), so a
4-tuple reused by a new socket is a new connection, and a state change on the same socket
(``SYN_SENT`` → ``ESTABLISHED``) is not reported as a new connection.

Noise control (documented, deliberate):
    * Sockets owned by PID 0 are not reported: they are lingering ``TIME_WAIT`` entries whose
      owner is already gone, so there is nothing to attribute.
    * UDP endpoints are reported as listeners only when bound to a port **below** the dynamic
      range (49152+). Windows binds ephemeral UDP ports constantly (DNS lookups, mDNS, SSDP); a
      non-ephemeral UDP bind is the interesting case.
    * A connection first observed already closing (``TIME_WAIT``, ``CLOSE_WAIT``…) is still
      reported as opened: polling caught it late, but it happened.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final

from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.core.models import (
    CorrelatedConnection,
    EventType,
    NetworkSnapshot,
    SecurityEvent,
    TransportProtocol,
)
from winsentinel.correlation.process_network import CandidateLookup, connection_record, correlate
from winsentinel.utils.networking import EPHEMERAL_PORT_START

SOURCE: Final = "network_monitor"


def is_reportable(item: CorrelatedConnection) -> bool:
    c = item.connection
    if c.pid == 0:
        return False
    if c.protocol is TransportProtocol.UDP:
        return c.local_port < EPHEMERAL_PORT_START
    return True


def _event_type(item: CorrelatedConnection, *, kind: str) -> EventType:
    listener = item.connection.is_listener
    return {
        ("discovered", True): EventType.LISTENER_DISCOVERED,
        ("discovered", False): EventType.CONNECTION_DISCOVERED,
        ("opened", True): EventType.LISTENER_OPENED,
        ("opened", False): EventType.CONNECTION_OPENED,
        ("closed", True): EventType.LISTENER_CLOSED,
        ("closed", False): EventType.CONNECTION_CLOSED,
    }[(kind, listener)]


def _event(item: CorrelatedConnection, event_type: EventType, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        timestamp=timestamp,
        source=SOURCE,
        process_key=item.process_key,
        pid=item.pid,
        data=connection_record(item),
    )


def inventory_events(
    items: Sequence[CorrelatedConnection], timestamp: datetime
) -> list[SecurityEvent]:
    return [
        _event(item, _event_type(item, kind="discovered"), timestamp)
        for item in items
        if is_reportable(item)
    ]


def diff_connections(
    previous: Mapping[str, CorrelatedConnection],
    current: Sequence[CorrelatedConnection],
    timestamp: datetime,
) -> list[SecurityEvent]:
    """Opened/closed events between two correlated socket sets. Pure function."""
    now = {item.connection.connection_key: item for item in current}
    events = [
        _event(item, _event_type(item, kind="opened"), timestamp)
        for key, item in now.items()
        if key not in previous and is_reportable(item)
    ]
    events.extend(
        _event(item, _event_type(item, kind="closed"), timestamp)
        for key, item in previous.items()
        if key not in now and is_reportable(item)
    )
    return events


class NetworkMonitor:
    """Collects, correlates and diffs sockets on each poll."""

    name: Final = "network_monitor"

    def __init__(
        self, collector: NetworkCollector, lookup: CandidateLookup, *, emit_inventory: bool = False
    ) -> None:
        self._collector = collector
        self._lookup = lookup
        self._emit_inventory = emit_inventory
        self._previous: dict[str, CorrelatedConnection] | None = None

    def poll(self) -> tuple[NetworkSnapshot, list[CorrelatedConnection], list[SecurityEvent]]:
        snapshot = self._collector.collect()
        items = correlate(snapshot.connections, self._lookup)
        if self._previous is None:
            events = inventory_events(items, snapshot.timestamp) if self._emit_inventory else []
        else:
            events = diff_connections(self._previous, items, snapshot.timestamp)
        self._previous = {item.connection.connection_key: item for item in items}
        return snapshot, items, events
