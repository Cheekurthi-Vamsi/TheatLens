"""Process collector (Phase 1).

What Windows APIs are used?
    * ``NtQuerySystemInformation(SystemProcessInformation)`` — **one call per snapshot** returns
      PID, PPID, image name, creation time, session, threads, handles, memory, CPU time and
      per-thread wait state for every process (see :mod:`threatlens.utils.ntapi`).
    * For each *newly seen* process, one ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)``
      handle serves ``QueryFullProcessImageNameW`` (exe), ``NtQueryInformationProcess`` (command
      line), ``GetTokenInformation`` (user, integrity) and ``IsWow64Process2`` (architecture).
      See :mod:`threatlens.utils.windows`.

Why is it needed?
    Processes are the unit every other signal is attributed to: sockets have owning PIDs,
    detections have subject processes, response actions have target processes.

What permissions does it require?
    None to enumerate. A standard user cannot open the token or read the command line of
    processes belonging to other users or SYSTEM (about half of all processes on a typical
    desktop). Administrators can, except for protected processes (PPL).

Limitations
    * Polling: processes living shorter than the interval are never seen.
    * The PPID is a creation-time value and can be spoofed; see ``correlation.process_tree``.
    * The command line comes from the target's PEB, which the process can overwrite. It is read
      at first sighting — as close to creation as polling allows — and cached.

Performance design
    Static fields (exe, command line, user, integrity, architecture) cannot change during a
    process's lifetime, so they are read once per process identity and cached; only the bulk
    counters are refreshed each snapshot. Steady-state cost is one system call plus parsing.

What happens if it fails?
    Per-field failures are recorded in :attr:`ProcessInfo.unavailable`; collection continues.
    Only failure of the bulk enumeration raises :class:`CollectorUnavailableError`.

Alternatives
    psutil per-process getters (O(n²) on Windows — measured ~2.4 s per snapshot for 273
    processes), WMI ``Win32_Process`` (slower), ETW / Sysmon (event-driven; admin/installation).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Final, Protocol, TypeVar

from threatlens.core.models import (
    Architecture,
    FieldIssue,
    IntegrityLevel,
    ProcessInfo,
    ProcessSnapshot,
    make_process_key,
)
from threatlens.errors import CollectorUnavailableError, InvalidInputError, ProcessNotFoundError
from threatlens.security.hashing import FileHasher, FileTooLargeError, NotARegularFileError
from threatlens.security.redaction import redact_command_line
from threatlens.security.signatures import SignatureVerifier
from threatlens.utils import windows
from threatlens.utils.ntapi import (
    HUNDRED_NS_PER_SECOND,
    SystemProcessEntry,
    SystemProcessQuery,
    query_image_name_by_pid,
)
from threatlens.utils.time import from_epoch, utc_now

logger = logging.getLogger(__name__)

T = TypeVar("T")

MAX_PID: Final = 0xFFFFFFFF
# PID 0 (System Idle Process) and PID 4 (System) are kernel pseudo processes: no image file,
# no PEB, no openable token.
PSEUDO_PROCESS_PIDS: Final = frozenset({0, 4})
# A brand-new process may not have its command line populated yet; do not cache an empty value
# read within this window after creation.
FRESH_PROCESS_SECONDS: Final = 2.0
STATIC_FIELDS: Final = ("exe", "cmdline", "username", "integrity_level", "architecture")


# --------------------------------------------------------------------------------------------
# OS abstractions (dependency-injection points; production implementations below)
# --------------------------------------------------------------------------------------------


class SystemProcessSource(Protocol):
    def query(self) -> Sequence[SystemProcessEntry]: ...


class ProcessDetailsReader(Protocol):
    def image_path(self) -> str: ...
    def argv(self) -> list[str]: ...
    def username(self) -> str: ...
    def integrity_rid(self) -> int: ...
    def machine(self) -> windows.MachineInfo: ...


class ProcessInspector(Protocol):
    def open(self, pid: int) -> AbstractContextManager[ProcessDetailsReader]:
        """Open the process; raises ``OSError`` if it cannot be opened at all."""
        ...

    def image_path_by_pid(self, pid: int) -> str:
        """Image path without a process handle (fallback when ``open`` is denied)."""
        ...


class _Win32DetailsReader(windows.ProcessQuery):
    def argv(self) -> list[str]:
        return windows.split_command_line(self.command_line())


class Win32ProcessInspector:
    """Production :class:`ProcessInspector`."""

    def __init__(self) -> None:
        self._accounts = windows.AccountResolver()
        self._devices = windows.DevicePathResolver()

    def open(self, pid: int) -> AbstractContextManager[ProcessDetailsReader]:
        return _Win32DetailsReader(pid, self._accounts)

    def image_path_by_pid(self, pid: int) -> str:
        nt_path = query_image_name_by_pid(pid)
        win32_path = self._devices.to_win32(nt_path)
        if win32_path is None:
            raise OSError(0, f"cannot map device path {nt_path!r} to a drive letter")
        return win32_path


# --------------------------------------------------------------------------------------------
# Pure translation helpers
# --------------------------------------------------------------------------------------------

_RID_UNTRUSTED_MAX: Final = 0x0FFF
_RID_LOW_MAX: Final = 0x1FFF
_RID_MEDIUM_MAX: Final = 0x2FFF
_RID_HIGH_MAX: Final = 0x3FFF


def integrity_from_rid(rid: int) -> IntegrityLevel:
    """Map a mandatory-label RID to a level.

    Ranges rather than exact values: Windows defines intermediate levels such as *MediumPlus*
    (0x2100, used by UIAccess processes).
    """
    if rid < 0:
        return IntegrityLevel.UNKNOWN
    if rid <= _RID_UNTRUSTED_MAX:
        return IntegrityLevel.UNTRUSTED
    if rid <= _RID_LOW_MAX:
        return IntegrityLevel.LOW
    if rid <= _RID_MEDIUM_MAX:
        return IntegrityLevel.MEDIUM
    if rid <= _RID_HIGH_MAX:
        return IntegrityLevel.HIGH
    return IntegrityLevel.SYSTEM


_MACHINES: Final[dict[int, Architecture]] = {
    windows.IMAGE_FILE_MACHINE_I386: Architecture.X86,
    windows.IMAGE_FILE_MACHINE_AMD64: Architecture.X64,
    windows.IMAGE_FILE_MACHINE_ARMNT: Architecture.ARM,
    windows.IMAGE_FILE_MACHINE_ARM64: Architecture.ARM64,
}


def architecture_from_machine(info: windows.MachineInfo) -> Architecture:
    """``process_machine == UNKNOWN`` means "not under WOW64", i.e. same as the OS."""
    machine = (
        info.native_machine
        if info.process_machine == windows.IMAGE_FILE_MACHINE_UNKNOWN
        else info.process_machine
    )
    return _MACHINES.get(machine, Architecture.UNKNOWN)


def issue_from_os_error(exc: OSError) -> FieldIssue:
    winerror = getattr(exc, "winerror", None)
    if winerror == windows.ERROR_ACCESS_DENIED or isinstance(exc, PermissionError):
        return FieldIssue.ACCESS_DENIED
    if winerror == windows.ERROR_INVALID_PARAMETER:
        return FieldIssue.PROCESS_EXITED
    return FieldIssue.ERROR


def validate_pid(pid: object) -> int:
    """Validate an untrusted PID value."""
    if isinstance(pid, bool) or not isinstance(pid, int) or not 0 <= pid <= MAX_PID:
        raise InvalidInputError(f"Invalid PID {pid!r}: must be an integer between 0 and {MAX_PID}")
    return pid


def cpu_percent(
    previous: tuple[int, float] | None, cpu_time_100ns: int, now: float, cpu_count: int
) -> float | None:
    """CPU share of total capacity between two samples ``(cpu_time_100ns, monotonic_seconds)``."""
    if previous is None:
        return None
    elapsed = now - previous[1]
    if elapsed <= 0:
        return None
    used_seconds = max(0, cpu_time_100ns - previous[0]) / HUNDRED_NS_PER_SECOND
    return round(min(100.0, used_seconds / (elapsed * cpu_count) * 100.0), 1)


# --------------------------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _StaticDetails:
    """Fields that cannot change during a process's lifetime, cached per process key."""

    exe: str | None
    cmdline: tuple[str, ...] | None
    username: str | None
    integrity_level: IntegrityLevel
    architecture: Architecture
    unavailable: dict[str, FieldIssue]


_TRANSIENT_ISSUES: Final = frozenset({FieldIssue.PROCESS_EXITED, FieldIssue.ERROR})


@dataclass(frozen=True, slots=True)
class ProcessCollectorOptions:
    redact_command_lines: bool = True


class ProcessCollector:
    """Produces :class:`ProcessSnapshot` objects. Not thread-safe; one instance per consumer."""

    name: Final = "process_collector"

    def __init__(
        self,
        source: SystemProcessSource | None = None,
        inspector: ProcessInspector | None = None,
        options: ProcessCollectorOptions | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        cpu_count: int | None = None,
    ) -> None:
        self._source = source or SystemProcessQuery()
        self._inspector = inspector or Win32ProcessInspector()
        self._options = options or ProcessCollectorOptions()
        self._clock = clock
        self._monotonic = monotonic
        self._cpu_count = max(1, cpu_count or os.cpu_count() or 1)
        self._static: dict[str, _StaticDetails] = {}
        self._cpu_samples: dict[str, tuple[int, float]] = {}

    # -- public API -------------------------------------------------------------------------

    def collect(self) -> ProcessSnapshot:
        """Enumerate all processes. Raises :class:`CollectorUnavailableError` on total failure."""
        entries, collected_at, now = self._query()
        processes = tuple(self._build(entry, collected_at, now) for entry in entries)
        self._prune({p.process_key for p in processes})
        return ProcessSnapshot(timestamp=collected_at, processes=processes)

    def collect_pid(self, pid: int, cpu_sample_seconds: float = 0.0) -> ProcessInfo:
        """Collect a single process without inspecting every other one.

        With ``cpu_sample_seconds > 0`` two samples are taken so CPU usage is populated.
        Raises :class:`ProcessNotFoundError` if the PID does not exist.
        """
        validate_pid(pid)
        info = self._collect_one(pid)
        if cpu_sample_seconds > 0:
            time.sleep(cpu_sample_seconds)
            refreshed = self._collect_one(pid)
            if refreshed.process_key == info.process_key:  # guard against PID reuse mid-sample
                info = refreshed
        return info

    @property
    def cached_process_count(self) -> int:
        return len(self._static)

    # -- internals --------------------------------------------------------------------------

    def _query(self) -> tuple[Sequence[SystemProcessEntry], datetime, float]:
        try:
            entries = self._source.query()
        except OSError as exc:
            raise CollectorUnavailableError(f"Process enumeration failed: {exc}") from exc
        return entries, self._clock(), self._monotonic()

    def _collect_one(self, pid: int) -> ProcessInfo:
        entries, collected_at, now = self._query()
        entry = next((e for e in entries if e.pid == pid), None)
        if entry is None:
            raise ProcessNotFoundError(pid)
        info = self._build(entry, collected_at, now)
        # Long-lived single-PID users (the engine's on-demand socket attribution) would otherwise
        # accumulate cache entries for processes that have since exited.
        self._prune({make_process_key(e.pid, from_epoch(e.create_time_epoch)) for e in entries})
        return info

    def _build(self, entry: SystemProcessEntry, collected_at: datetime, now: float) -> ProcessInfo:
        create_time = from_epoch(entry.create_time_epoch)
        key = make_process_key(entry.pid, create_time)

        static = self._static.get(key)
        if static is None:
            static = self._read_static(entry.pid)
            self._maybe_cache(key, static, create_time, collected_at)

        previous = self._cpu_samples.get(key)
        self._cpu_samples[key] = (entry.cpu_time_100ns, now)

        return ProcessInfo(
            pid=entry.pid,
            # Pseudo processes report PPID 0, which is not a real parent.
            ppid=None if entry.pid in PSEUDO_PROCESS_PIDS and entry.ppid == 0 else entry.ppid,
            name=entry.image_name or f"<pid {entry.pid}>",
            exe=static.exe,
            cmdline=static.cmdline,
            username=static.username,
            create_time=create_time,
            cpu_percent=cpu_percent(previous, entry.cpu_time_100ns, now, self._cpu_count),
            working_set=entry.working_set,
            private_bytes=entry.private_bytes,
            num_threads=entry.num_threads,
            handle_count=entry.handle_count,
            session_id=entry.session_id,
            integrity_level=static.integrity_level,
            architecture=static.architecture,
            suspended=entry.all_threads_suspended,
            unavailable=dict(static.unavailable),
            collected_at=collected_at,
        )

    def _read_static(self, pid: int) -> _StaticDetails:
        unavailable: dict[str, FieldIssue] = {}
        if pid in PSEUDO_PROCESS_PIDS:
            return _StaticDetails(
                exe=None,
                cmdline=None,
                username=None,
                integrity_level=IntegrityLevel.UNKNOWN,
                architecture=Architecture.UNKNOWN,
                unavailable=dict.fromkeys(STATIC_FIELDS, FieldIssue.NOT_APPLICABLE),
            )

        def read(field_name: str, getter: Callable[[], T]) -> T | None:
            try:
                return getter()
            except OSError as exc:
                unavailable[field_name] = issue_from_os_error(exc)
                return None

        exe: str | None = None
        argv: list[str] | None = None
        username: str | None = None
        rid: int | None = None
        machine: windows.MachineInfo | None = None
        try:
            with self._inspector.open(pid) as reader:
                exe = read("exe", reader.image_path)
                argv = read("cmdline", reader.argv)
                username = read("username", reader.username)
                rid = read("integrity_level", reader.integrity_rid)
                machine = read("architecture", reader.machine)
        except OSError as exc:
            unavailable.update(dict.fromkeys(STATIC_FIELDS, issue_from_os_error(exc)))

        # The handle was denied (typical for SYSTEM processes as a standard user): the kernel will
        # still tell us the image path by PID.
        if exe is None and unavailable.get("exe") in (FieldIssue.ACCESS_DENIED, FieldIssue.ERROR):
            try:
                exe = self._inspector.image_path_by_pid(pid)
                del unavailable["exe"]
            except OSError as exc:
                logger.debug("event=IMAGE_PATH_FALLBACK_FAILED pid=%s error=%s", pid, exc)

        # Minimal processes (Registry, MemCompression, vmmem) report a bare name, not a path.
        if exe is not None and not PureWindowsPath(exe).is_absolute():
            exe = None
            unavailable["exe"] = FieldIssue.NOT_APPLICABLE

        cmdline: tuple[str, ...] | None = None
        if argv is not None:
            cmdline = (
                redact_command_line(argv) if self._options.redact_command_lines else tuple(argv)
            )

        return _StaticDetails(
            exe=exe,
            cmdline=cmdline,
            username=username or None,
            integrity_level=IntegrityLevel.UNKNOWN if rid is None else integrity_from_rid(rid),
            architecture=(
                Architecture.UNKNOWN if machine is None else architecture_from_machine(machine)
            ),
            unavailable=unavailable,
        )

    def _maybe_cache(
        self,
        key: str,
        static: _StaticDetails,
        create_time: datetime | None,
        collected_at: datetime,
    ) -> None:
        if _TRANSIENT_ISSUES & set(static.unavailable.values()):
            return  # retry next snapshot
        is_fresh = (
            create_time is not None
            and (collected_at - create_time).total_seconds() < FRESH_PROCESS_SECONDS
        )
        if is_fresh and not static.cmdline:
            return  # PEB may not be populated yet
        self._static[key] = static

    def _prune(self, live_keys: set[str]) -> None:
        for key in self._static.keys() - live_keys:
            del self._static[key]
        for key in self._cpu_samples.keys() - live_keys:
            del self._cpu_samples[key]


# --------------------------------------------------------------------------------------------
# Enrichment (expensive, on demand)
# --------------------------------------------------------------------------------------------


class ProcessEnricher:
    """Adds SHA256 and signature to a :class:`ProcessInfo`.

    Kept separate from collection because hashing and ``WinVerifyTrust`` are I/O-heavy. Both are
    cached by file fingerprint, so enriching 300 processes that share 80 executables verifies 80
    files once, then nothing until a file changes.
    """

    def __init__(
        self,
        hasher: FileHasher | None = None,
        verifier: SignatureVerifier | None = None,
        *,
        verify_signatures: bool = True,
    ) -> None:
        self._hasher = hasher or FileHasher()
        self._verifier = verifier or SignatureVerifier()
        self._verify_signatures = verify_signatures

    def enrich(self, info: ProcessInfo) -> ProcessInfo:
        if info.exe is None:
            return info
        unavailable = dict(info.unavailable)
        sha256: str | None = None
        try:
            sha256 = self._hasher.sha256(info.exe)
        except FileTooLargeError:
            unavailable["sha256"] = FieldIssue.TOO_LARGE
        except PermissionError:
            unavailable["sha256"] = FieldIssue.ACCESS_DENIED
        except (OSError, NotARegularFileError) as exc:
            unavailable["sha256"] = FieldIssue.ERROR
            logger.debug("event=HASH_FAILED pid=%s error=%s", info.pid, exc)

        signature = self._verifier.verify(info.exe) if self._verify_signatures else None
        return info.model_copy(
            update={"sha256": sha256, "signature": signature, "unavailable": unavailable}
        )
