"""Rule registry. Adding a rule = write the class, add it here, add tests and documentation."""

from __future__ import annotations

from typing import Final

from winsentinel.core.models import RuleMetadata
from winsentinel.detection.rules.base import Rule
from winsentinel.detection.rules.execution import (
    LolbinProxyExecution,
    SuspiciousParentChild,
    SuspiciousPowerShell,
    UnusualExecutionChain,
)
from winsentinel.detection.rules.file import ExecutableDroppedInSensitiveLocation
from winsentinel.detection.rules.network import (
    FirstSeenExecutableOutbound,
    HighFrequencyOutbound,
    NewListeningPort,
    NewProcessExternalConnection,
    UncommonRemotePort,
)
from winsentinel.detection.rules.origin import (
    DeceptiveFileName,
    InvalidSignature,
    SystemBinaryMasquerading,
    TempDirectoryExecution,
    UnsignedUserWritableExecutable,
)
from winsentinel.detection.rules.persistence import NewAutorunEntry, NewScheduledTaskOrService
from winsentinel.detection.settings import DetectionSettings

RULE_CLASSES: Final[tuple[type[Rule], ...]] = (
    TempDirectoryExecution,
    UnsignedUserWritableExecutable,
    SuspiciousParentChild,
    NewProcessExternalConnection,
    SystemBinaryMasquerading,
    SuspiciousPowerShell,
    LolbinProxyExecution,
    DeceptiveFileName,
    FirstSeenExecutableOutbound,
    NewListeningPort,
    HighFrequencyOutbound,
    UncommonRemotePort,
    UnusualExecutionChain,
    InvalidSignature,
    NewAutorunEntry,
    NewScheduledTaskOrService,
    ExecutableDroppedInSensitiveLocation,
)


def build_rules(settings: DetectionSettings) -> list[Rule]:
    """Fresh rule instances (stateful rules keep per-instance history)."""
    return [cls(settings) for cls in RULE_CLASSES]


def rule_catalog() -> list[RuleMetadata]:
    return sorted((cls.meta for cls in RULE_CLASSES), key=lambda meta: meta.rule_id)


__all__ = ["RULE_CLASSES", "Rule", "build_rules", "rule_catalog"]
