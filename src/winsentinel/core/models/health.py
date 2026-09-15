"""Engine self-observation models (Phase 4, docs/architecture.md §53)."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, Field

from winsentinel.core.models.common import Frozen, Pid

STATUS_SCHEMA_VERSION: Final = 1


class ComponentStatus(StrEnum):
    STARTING = "STARTING"
    OK = "OK"
    DEGRADED = "DEGRADED"  # recent failure(s); still retrying on a short backoff
    UNAVAILABLE = "UNAVAILABLE"  # repeated failures; retrying on the maximum backoff
    TIMED_OUT = "TIMED_OUT"  # current run exceeded its timeout; other components unaffected
    STOPPED = "STOPPED"
    DISABLED = "DISABLED"  # turned off in configuration


class ComponentHealth(Frozen):
    name: str
    status: ComponentStatus
    runs: int = Field(default=0, ge=0)
    failures: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    last_success: AwareDatetime | None = None
    last_error: str | None = None
    last_error_at: AwareDatetime | None = None
    last_duration_ms: float | None = None
    detail: str | None = None


class BusStats(Frozen):
    capacity: int
    queued: int
    published: int
    dispatched: int
    dropped: int
    handler_errors: int
    avg_latency_ms: float | None = None


class EngineState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class EngineStats(Frozen):
    processes: int = 0
    exited_retained: int = 0
    connections: int = 0
    enriched: int = 0
    detections: int = 0
    events_per_second: float | None = None


class EngineStatus(Frozen):
    """Written atomically by a running engine; read by ``winsentinel status``."""

    schema_version: int = STATUS_SCHEMA_VERSION
    version: str
    pid: Pid
    process_key: str | None = None
    state: EngineState
    started_at: AwareDatetime
    updated_at: AwareDatetime
    interval_seconds: float
    components: tuple[ComponentHealth, ...]
    bus: BusStats
    stats: EngineStats
    rules_enabled: int = 0
    engine_cpu_percent: float | None = None
    engine_working_set: int | None = None
