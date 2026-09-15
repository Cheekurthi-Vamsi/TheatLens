"""Central style definitions so severity/trust colours are consistent everywhere."""

from __future__ import annotations

from typing import Final

from winsentinel.core.models import IntegrityLevel, Severity, SignatureStatus

MUTED: Final = "grey50"
LABEL: Final = "bold cyan"
HEADER: Final = "bold"
WARNING: Final = "yellow"
ERROR: Final = "bold red"
OK: Final = "green"

SEVERITY_STYLES: Final[dict[Severity, str]] = {
    Severity.NORMAL: "green",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold dark_orange",
    Severity.CRITICAL: "bold white on red",
}

SIGNATURE_STYLES: Final[dict[SignatureStatus, str]] = {
    SignatureStatus.VALID: "green",
    SignatureStatus.UNSIGNED: "yellow",
    SignatureStatus.INVALID: "bold red",
    SignatureStatus.UNKNOWN: MUTED,
}

INTEGRITY_STYLES: Final[dict[IntegrityLevel, str]] = {
    IntegrityLevel.SYSTEM: "magenta",
    IntegrityLevel.HIGH: "bold yellow",
    IntegrityLevel.MEDIUM: "default",
    IntegrityLevel.LOW: "cyan",
    IntegrityLevel.UNTRUSTED: "cyan",
    IntegrityLevel.UNKNOWN: MUTED,
}
