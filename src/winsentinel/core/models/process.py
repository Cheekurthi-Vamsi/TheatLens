"""Process domain models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import AwareDatetime, Field, computed_field

from winsentinel.core.models.common import FieldIssue, Frozen, Pid
from winsentinel.utils.time import utc_now


class SignatureStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNSIGNED = "UNSIGNED"
    UNKNOWN = "UNKNOWN"


class SignatureSource(StrEnum):
    EMBEDDED = "EMBEDDED"
    CATALOG = "CATALOG"
    PACKAGE = "PACKAGE"  # MSIX/AppX: signature covers the package, not the individual file
    NONE = "NONE"


class IntegrityLevel(StrEnum):
    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SYSTEM = "SYSTEM"
    UNKNOWN = "UNKNOWN"


class Architecture(StrEnum):
    X86 = "X86"
    X64 = "X64"
    ARM = "ARM"
    ARM64 = "ARM64"
    UNKNOWN = "UNKNOWN"


def make_process_key(pid: int, create_time: datetime | None) -> str:
    """Return a stable identity for a process instance.

    Windows reuses PIDs quickly, so ``pid`` alone is not an identity. The pair
    ``(pid, creation time)`` is unique for the lifetime of the boot session. System pseudo
    processes (PID 0 and 4) report no creation time and get ``"<pid>:0"``.
    """
    millis = 0 if create_time is None else int(create_time.timestamp() * 1000)
    return f"{pid}:{millis}"


class SignatureInfo(Frozen):
    """Authenticode verification result for a file.

    ``signer`` is populated **only** for ``VALID`` signatures: the subject name inside an invalid
    or untrusted signature is attacker-controlled text and must not be displayed as a publisher.
    """

    status: SignatureStatus
    source: SignatureSource = SignatureSource.NONE
    signer: str | None = None
    error_code: int | None = Field(default=None, description="Raw HRESULT from WinVerifyTrust")
    detail: str | None = None


class ProcessInfo(Frozen):
    """A point-in-time snapshot of one process as observed by the process collector."""

    pid: Pid
    ppid: Pid | None
    name: str
    exe: str | None = None
    cmdline: tuple[str, ...] | None = None
    username: str | None = None
    create_time: AwareDatetime | None = None
    cpu_percent: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Share of total CPU capacity (0-100); None until two samples exist",
    )
    working_set: int | None = Field(default=None, ge=0, description="Physical memory, bytes")
    private_bytes: int | None = Field(default=None, ge=0, description="Committed private memory")
    num_threads: int | None = Field(default=None, ge=0)
    handle_count: int | None = Field(default=None, ge=0)
    session_id: int | None = Field(default=None, ge=0)
    integrity_level: IntegrityLevel = IntegrityLevel.UNKNOWN
    architecture: Architecture = Architecture.UNKNOWN
    suspended: bool | None = None
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signature: SignatureInfo | None = None
    unavailable: dict[str, FieldIssue] = Field(default_factory=dict)
    collected_at: AwareDatetime = Field(default_factory=utc_now)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def process_key(self) -> str:
        return make_process_key(self.pid, self.create_time)

    @property
    def command_line(self) -> str | None:
        """Command line joined for display (arguments already redacted by the collector)."""
        return None if self.cmdline is None else " ".join(self.cmdline)


class ProcessSnapshot(Frozen):
    """All processes observed in one enumeration pass.

    ``skipped`` counts processes that appeared in the enumeration but whose identity (name, PPID,
    creation time) could not be read — usually because they exited mid-pass.
    """

    timestamp: AwareDatetime
    processes: tuple[ProcessInfo, ...]
    skipped: int = Field(default=0, ge=0)

    def by_key(self) -> dict[str, ProcessInfo]:
        return {p.process_key: p for p in self.processes}

    def by_pid(self) -> dict[int, ProcessInfo]:
        return {p.pid: p for p in self.processes}


class ProcessNode(Frozen):
    """A process in a reconstructed tree.

    ``parent_verified`` is ``False`` when the reported parent PID either no longer exists or now
    belongs to a *newer* process (PID reuse) — the node is then shown as a root rather than
    attached to an unrelated parent.
    """

    process: ProcessInfo
    children: tuple[ProcessNode, ...] = ()
    parent_verified: bool = True


ProcessNode.model_rebuild()  # resolve the self-reference under postponed annotations
