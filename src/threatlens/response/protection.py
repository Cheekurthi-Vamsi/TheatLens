"""Protected-process policy (docs/architecture.md §40).

Terminating or suspending a critical Windows process crashes the machine (bugcheck) or logs the
user out. This module decides whether a process is protected and *why*, so the CLI can refuse or
demand an explicit override. It is intentionally conservative: when unsure, it protects.

A process is protected when any of these hold:
    * its image name is on the configured critical-process list (``response.protected_processes``);
    * it is a kernel pseudo-process (PID 0 or 4) or ``wininit``/``winlogon``/``smss`` by lineage;
    * it runs at SYSTEM integrity (killing SYSTEM services is how you blue-screen a box);
    * it is ThreatLens's own process (never let the tool suspend or kill itself).

Overriding protection requires an explicit advanced flag *and* confirmation (see the CLI).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from threatlens.core.models import IntegrityLevel, ProcessInfo

# Always protected regardless of configuration — killing these is catastrophic.
ALWAYS_PROTECTED_PIDS: Final = frozenset({0, 4})
ALWAYS_PROTECTED_NAMES: Final = frozenset(
    {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe"}
)


@dataclass(frozen=True, slots=True)
class ProtectionVerdict:
    protected: bool
    reasons: tuple[str, ...] = ()

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons)


class ProtectionPolicy:
    def __init__(self, protected_names: frozenset[str], *, own_pid: int | None = None) -> None:
        self._names = {n.lower() for n in protected_names} | ALWAYS_PROTECTED_NAMES
        self._own_pid = os.getpid() if own_pid is None else own_pid

    def evaluate(self, process: ProcessInfo) -> ProtectionVerdict:
        reasons: list[str] = []
        if process.pid == self._own_pid:
            reasons.append("this is ThreatLens's own process")
        if process.pid in ALWAYS_PROTECTED_PIDS:
            reasons.append("kernel pseudo-process")
        if process.name.lower() in self._names:
            reasons.append(f"{process.name} is a critical/protected process")
        if process.integrity_level is IntegrityLevel.SYSTEM:
            reasons.append("runs at SYSTEM integrity (a core OS/service process)")
        return ProtectionVerdict(protected=bool(reasons), reasons=tuple(reasons))
