"""Protocols between layers (docs/architecture.md §8).

Rules depend on :class:`StateView`, not on the concrete
:class:`~winsentinel.core.state.SystemState`, so each rule can be tested against a small hand-built
state and never gains write access.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from winsentinel.core.models import (
    CorrelatedConnection,
    DetectionResult,
    ProcessInfo,
    RuleMetadata,
    SecurityEvent,
)


class StateView(Protocol):
    """Read-only view of the host that detection rules receive."""

    def now(self) -> datetime: ...
    def process(self, process_key: str) -> ProcessInfo | None: ...
    def process_by_pid(self, pid: int) -> ProcessInfo | None: ...
    def parent_of(self, process: ProcessInfo) -> ProcessInfo | None: ...
    def ancestors(self, process: ProcessInfo, limit: int = 16) -> list[ProcessInfo]: ...
    def connections_of(self, process_key: str) -> list[CorrelatedConnection]: ...
    def events_for(
        self, process_key: str, within: timedelta | None = None
    ) -> list[SecurityEvent]: ...


class DetectionRule(Protocol):
    """A plugin-like detection rule. Rules observe and explain; they never act."""

    @property
    def meta(self) -> RuleMetadata: ...

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None: ...
