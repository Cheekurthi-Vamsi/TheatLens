"""Alert and risk-scoring models (Phase 6, docs/architecture.md §11, §22)."""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, Field, computed_field

from winsentinel.core.models.common import Confidence, Frozen, Pid, Severity, severity_for_score
from winsentinel.core.models.detection import DetectionResult, NetworkContext

MAX_RISK: Final = 100


class AlertStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


# Statuses the user sets; once one of these is set, new detections do not silently reopen it.
TERMINAL_STATUSES: Final = frozenset({AlertStatus.RESOLVED, AlertStatus.IGNORED})


class ScoreContribution(Frozen):
    """One rule's contribution to an alert's combined risk (docs/architecture.md §11)."""

    rule_id: str
    rule_name: str
    category: str
    raw_score: int = Field(ge=0)
    confidence: Confidence
    effective: float = Field(ge=0, description="raw_score x confidence weight x context modifier")
    detection_id: str


class Alert(Frozen):
    """A scored, explainable judgement about one process instance.

    An alert is a *combination* of detections, not a verdict. It never asserts "malware"; the
    title and severity describe suspicion and the breakdown shows exactly how the score was built.
    """

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: AwareDatetime
    updated_at: AwareDatetime
    title: str
    risk_score: int = Field(ge=0, le=MAX_RISK)
    confidence: Confidence
    status: AlertStatus = AlertStatus.NEW
    process_key: str | None = None
    pid: Pid | None = None
    process_name: str | None = None
    exe: str | None = None
    detections: tuple[DetectionResult, ...] = Field(min_length=1)
    score_breakdown: tuple[ScoreContribution, ...] = Field(min_length=1)
    network: tuple[NetworkContext, ...] = ()
    recommended_actions: tuple[str, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> Severity:
        return severity_for_score(self.risk_score)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rules_triggered(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(d.rule_id for d in self.detections))
