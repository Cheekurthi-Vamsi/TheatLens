"""The event envelope (docs/architecture.md §9)."""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any, Final

from pydantic import AwareDatetime, Field

from winsentinel.core.models.common import Frozen, Observation, Pid
from winsentinel.utils.time import utc_now

EVENT_SCHEMA_VERSION: Final = 1


class EventType(StrEnum):
    # Process lifecycle. DISCOVERED = already running when monitoring began (not "started now").
    PROCESS_DISCOVERED = "PROCESS_DISCOVERED"
    PROCESS_STARTED = "PROCESS_STARTED"
    PROCESS_STOPPED = "PROCESS_STOPPED"
    PROCESS_CHANGED = "PROCESS_CHANGED"
    PROCESS_ENRICHED = "PROCESS_ENRICHED"  # SHA256 + signature became available
    # Network
    CONNECTION_DISCOVERED = "CONNECTION_DISCOVERED"
    CONNECTION_OPENED = "CONNECTION_OPENED"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    LISTENER_DISCOVERED = "LISTENER_DISCOVERED"
    LISTENER_OPENED = "LISTENER_OPENED"
    LISTENER_CLOSED = "LISTENER_CLOSED"
    # File activity in monitored locations
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    FILE_RENAMED = "FILE_RENAMED"
    # Persistence / autostart
    PERSISTENCE_DISCOVERED = "PERSISTENCE_DISCOVERED"
    PERSISTENCE_ADDED = "PERSISTENCE_ADDED"
    PERSISTENCE_REMOVED = "PERSISTENCE_REMOVED"
    PERSISTENCE_CHANGED = "PERSISTENCE_CHANGED"
    # Engine self-observation
    COLLECTOR_STATUS = "COLLECTOR_STATUS"


INVENTORY_EVENT_TYPES: Final = frozenset(
    {
        EventType.PROCESS_DISCOVERED,
        EventType.CONNECTION_DISCOVERED,
        EventType.LISTENER_DISCOVERED,
        EventType.PERSISTENCE_DISCOVERED,
    }
)


class SecurityEvent(Frozen):
    """Envelope for every observation flowing through the engine."""

    schema_version: int = EVENT_SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    timestamp: AwareDatetime = Field(default_factory=utc_now)
    source: str
    observation: Observation = Observation.OBSERVED
    process_key: str | None = None
    pid: Pid | None = None
    data: dict[str, Any] = Field(default_factory=dict)
