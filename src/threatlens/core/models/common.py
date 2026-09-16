"""Shared model building blocks and enums used across domains."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    """Base for all domain models: immutable, and unknown fields are an error."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=False)


Pid = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
Port = Annotated[int, Field(ge=0, le=65535)]


class Severity(StrEnum):
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    """How reliably a signal indicates genuinely suspicious activity (not observation certainty)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Observation(StrEnum):
    """How a fact became known — the UI must never present an inference as an observation."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED = "CONFIRMED"


class FieldIssue(StrEnum):
    """Why a field could not be populated."""

    ACCESS_DENIED = "ACCESS_DENIED"
    PROCESS_EXITED = "PROCESS_EXITED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    TOO_LARGE = "TOO_LARGE"
    ERROR = "ERROR"


# Risk bands from docs/architecture.md §11: (inclusive lower bound, severity), highest first.
SEVERITY_BANDS: Final[tuple[tuple[int, Severity], ...]] = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0, Severity.NORMAL),
)


def severity_for_score(score: int) -> Severity:
    """Map a 0-100 score to its severity band."""
    for lower_bound, severity in SEVERITY_BANDS:
        if score >= lower_bound:
            return severity
    return Severity.NORMAL
