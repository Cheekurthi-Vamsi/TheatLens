"""Detection models (Phase 5, docs/architecture.md §10)."""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Annotated, Final

from pydantic import AwareDatetime, Field

from winsentinel.core.models.common import (
    Confidence,
    Frozen,
    Observation,
    Pid,
    Severity,
    severity_for_score,
)
from winsentinel.core.models.events import EventType
from winsentinel.utils.time import utc_now

MAX_RULE_SCORE: Final = 60  # no single rule may reach HIGH/CRITICAL on its own

RuleId = Annotated[str, Field(pattern=r"^[A-Z]{2,8}-\d{3}$")]
MitreTechnique = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]


class RuleCategory(StrEnum):
    ORIGIN = "ORIGIN"  # where an executable lives
    SIGNATURE = "SIGNATURE"
    LINEAGE = "LINEAGE"  # who started whom
    EXECUTION = "EXECUTION"  # how it was invoked (command line)
    MASQUERADE = "MASQUERADE"  # pretending to be something else
    NETWORK = "NETWORK"
    PERSISTENCE = "PERSISTENCE"
    BASELINE = "BASELINE"


class Evidence(Frozen):
    """One fact supporting a detection, labelled with how it became known."""

    description: str = Field(min_length=1)
    observation: Observation = Observation.OBSERVED
    field: str | None = None
    value: str | None = None


class NetworkContext(Frozen):
    protocol: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str
    direction: str
    remote_scope: str | None = None


class RuleMetadata(Frozen):
    rule_id: RuleId
    name: str
    description: str
    rationale: str
    category: RuleCategory
    event_types: tuple[EventType, ...] = Field(min_length=1)
    base_score: int = Field(ge=1, le=MAX_RULE_SCORE)
    confidence: Confidence
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    false_positives: tuple[str, ...] = Field(min_length=1)
    recommendation: str
    enabled_by_default: bool = True

    @property
    def default_severity(self) -> Severity:
        return severity_for_score(self.base_score)


class DetectionResult(Frozen):
    """A rule's verdict on one subject. It is a *signal* with evidence, never a conclusion."""

    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: RuleId
    rule_name: str
    category: RuleCategory
    timestamp: AwareDatetime = Field(default_factory=utc_now)
    score: int = Field(ge=0, le=MAX_RULE_SCORE)
    confidence: Confidence
    summary: str
    evidence: tuple[Evidence, ...] = Field(min_length=1)
    process_key: str | None = None
    pid: Pid | None = None
    process_name: str | None = None
    exe: str | None = None
    network: tuple[NetworkContext, ...] = ()
    event_ids: tuple[str, ...] = ()
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    dedup_key: str = ""
