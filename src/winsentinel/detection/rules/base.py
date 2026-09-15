"""Shared building blocks for detection rules."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from winsentinel.core.interfaces import StateView
from winsentinel.core.models import (
    Confidence,
    CorrelatedConnection,
    DetectionResult,
    Evidence,
    NetworkContext,
    Observation,
    ProcessInfo,
    RuleMetadata,
    SecurityEvent,
    SignatureStatus,
)
from winsentinel.correlation.process_network import connection_record
from winsentinel.detection.settings import DetectionSettings

MAX_DEFERRED_PROCESSES: Final = 4096
MAX_DEFERRED_PER_PROCESS: Final = 32
MAX_EVIDENCE_CONNECTIONS: Final = 3


def observed(description: str, field: str | None = None, value: object | None = None) -> Evidence:
    return Evidence(
        description=description,
        observation=Observation.OBSERVED,
        field=field,
        value=None if value is None else str(value),
    )


def inferred(description: str, field: str | None = None, value: object | None = None) -> Evidence:
    return Evidence(
        description=description,
        observation=Observation.INFERRED,
        field=field,
        value=None if value is None else str(value),
    )


def is_validly_signed(process: ProcessInfo) -> bool:
    return process.signature is not None and process.signature.status is SignatureStatus.VALID


def enrichment_pending(process: ProcessInfo) -> bool:
    """True until background hashing/signature verification has produced a result."""
    return (
        process.exe is not None
        and process.signature is None
        and process.sha256 is None
        and "sha256" not in process.unavailable
    )


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ConnectionFacts:
    """Uniform view of a socket from either an event payload or correlated state."""

    connection_key: str
    process_key: str | None
    pid: int
    exe: str | None
    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    state: str
    direction: str
    local_scope: str | None
    remote_scope: str | None
    attribution: str
    created_at: datetime | None

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> ConnectionFacts:
        return cls(
            connection_key=str(data.get("connection_key", "")),
            process_key=data.get("process_key"),
            pid=int(data.get("pid") or 0),
            exe=data.get("exe"),
            protocol=str(data.get("protocol", "")),
            local_address=str(data.get("local_address", "")),
            local_port=int(data.get("local_port") or 0),
            remote_address=data.get("remote_address"),
            remote_port=data.get("remote_port"),
            state=str(data.get("state", "")),
            direction=str(data.get("direction", "")),
            local_scope=data.get("local_scope"),
            remote_scope=data.get("remote_scope"),
            attribution=str(data.get("attribution", "")),
            created_at=_parse_time(data.get("created_at")),
        )

    @classmethod
    def from_item(cls, item: CorrelatedConnection) -> ConnectionFacts:
        return cls.from_data(connection_record(item))

    @property
    def is_public_outbound(self) -> bool:
        return self.remote_scope == "PUBLIC" and self.direction == "OUTBOUND"

    @property
    def endpoint(self) -> str:
        host = (
            f"[{self.remote_address}]"
            if self.remote_address and ":" in self.remote_address
            else self.remote_address
        )
        return f"{host}:{self.remote_port}"

    def context(self) -> NetworkContext:
        return NetworkContext(
            protocol=self.protocol,
            local_port=self.local_port,
            remote_address=self.remote_address,
            remote_port=self.remote_port,
            state=self.state,
            direction=self.direction,
            remote_scope=self.remote_scope,
        )


class Rule:
    """Base class: subclasses set ``meta`` and implement :meth:`evaluate`."""

    meta: RuleMetadata

    def __init__(self, settings: DetectionSettings) -> None:
        self.settings = settings

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------------------------

    @staticmethod
    def subject(event: SecurityEvent, state: StateView) -> ProcessInfo | None:
        return None if event.process_key is None else state.process(event.process_key)

    def is_excluded_by_trust(self, process: ProcessInfo) -> bool:
        """Trusted location or valid signature: context in which most rules stay silent."""
        return (
            process.exe is None
            or self.settings.paths.is_trusted(process.exe)
            or is_validly_signed(process)
        )

    def result(
        self,
        *,
        process: ProcessInfo | None,
        evidence: Sequence[Evidence],
        detail: str,
        event: SecurityEvent | None = None,
        score: int | None = None,
        confidence: Confidence | None = None,
        network: Iterable[NetworkContext] = (),
        dedup_key: str = "",
        mitre: Sequence[str] | None = None,
    ) -> DetectionResult:
        who = f"{process.name} (PID {process.pid})" if process else "unattributed activity"
        return DetectionResult(
            rule_id=self.meta.rule_id,
            rule_name=self.meta.name,
            category=self.meta.category,
            score=self.meta.base_score if score is None else min(score, self.meta.base_score),
            confidence=confidence or self.meta.confidence,
            summary=f"{who}: {detail}",
            evidence=tuple(evidence),
            process_key=process.process_key if process else None,
            pid=process.pid if process else None,
            process_name=process.name if process else None,
            exe=process.exe if process else None,
            network=tuple(network),
            event_ids=() if event is None else (event.event_id,),
            mitre_techniques=tuple(mitre) if mitre is not None else self.meta.mitre_techniques,
            dedup_key=dedup_key,
        )


class EnrichmentDeferral:
    """Parks connection facts for processes whose signature is not yet known.

    Bounded both in processes and in facts per process; the oldest process entries are evicted.
    """

    def __init__(self) -> None:
        self._pending: OrderedDict[str, list[ConnectionFacts]] = OrderedDict()

    def park(self, process_key: str, facts: ConnectionFacts) -> None:
        bucket = self._pending.setdefault(process_key, [])
        self._pending.move_to_end(process_key)
        if len(bucket) < MAX_DEFERRED_PER_PROCESS:
            bucket.append(facts)
        while len(self._pending) > MAX_DEFERRED_PROCESSES:
            self._pending.popitem(last=False)

    def release(self, process_key: str) -> list[ConnectionFacts]:
        return self._pending.pop(process_key, [])
