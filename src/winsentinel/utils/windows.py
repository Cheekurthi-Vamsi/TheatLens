"""Thin, typed ctypes wrappers around Win32 APIs used for per-process inspection.

Why ctypes and not psutil/pywin32 here?
    Profiling showed psutil's per-process getters re-enumerate the whole system on every call on
    Windows. Opening **one** handle per new process and reading every static field from it is an
    order of magnitude cheaper, and it keeps each Windows API call visible to someone learning
    the internals. Every foreign function declares ``argtypes``/``restype`` — without
    ``restype = HANDLE`` a 64-bit handle is silently truncated to 32 bits.

Error contract
    Methods raise :class:`OSError` with ``winerror`` set. Common codes:

    * ``ERROR_ACCESS_DENIED`` (5) — other user / SYSTEM / protected (PPL) target.
    * ``ERROR_INVALID_PARAMETER`` (87) — from ``OpenProcess``: the PID no longer exists.

Raw Windows values (RIDs, machine constants) are returned; translation into domain enums lives
in the collector so this module stays free of domain imports.
"""

from __future__ import annotations

import ctypes
import platform
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from types import TracebackType
from typing import Final, Self

from winsentinel.errors import PlatformNotSupportedError

ERROR_ACCESS_DENIED: Final = 5
ERROR_BAD_LENGTH: Final = 24
ERROR_INVALID_PARAMETER: Final = 87
ERROR_INSUFFICIENT_BUFFER: Final = 122
ERROR_NONE_MAPPED: Final = 1332

PROCESS_QUERY_LIMITED_INFORMATION: Final = 0x1000
PROCESS_SUSPEND_RESUME: Final = 0x0800
PROCESS_TERMINATE: Final = 0x0001
TOKEN_QUERY: Final = 0x0008

# TOKEN_INFORMATION_CLASS (winnt.h)
TOKEN_USER_CLASS: Final = 1
TOKEN_ELEVATION_CLASS: Final = 20
TOKEN_INTEGRITY_LEVEL_CLASS: Final = 25

# PROCESSINFOCLASS (ntpsapi.h): available since Windows 8.1 with QUERY_LIMITED access
PROCESS_COMMAND_LINE_INFORMATION: Final = 60
STATUS_INFO_LENGTH_MISMATCH: Final = 0xC0000004
STATUS_BUFFER_OVERFLOW: Final = 0x80000005
STATUS_BUFFER_TOO_SMALL: Final = 0xC0000023

# IMAGE_FILE_MACHINE_* (winnt.h)
IMAGE_FILE_MACHINE_UNKNOWN: Final = 0x0000
IMAGE_FILE_MACHINE_I386: Final = 0x014C
IMAGE_FILE_MACHINE_ARMNT: Final = 0x01C4
IMAGE_FILE_MACHINE_AMD64: Final = 0x8664
IMAGE_FILE_MACHINE_ARM64: Final = 0xAA64

WINDOWS_10_FIRST_BUILD: Final = 10240
WINDOWS_11_FIRST_BUILD: Final = 22000

_MAX_IMAGE_PATH: Final = 32_768
_MAX_COMMAND_LINE_BYTES: Final = 1024 * 1024


def is_windows() -> bool:
    return sys.platform == "win32"


def _require_windows() -> None:
    if not is_windows():
        raise PlatformNotSupportedError("This operation requires Windows.")


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD))


class _UnicodeString(ctypes.Structure):
    _fields_ = (
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    )


if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenProcess.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = [wintypes.HLOCAL]
    _LocalFree.restype = wintypes.HLOCAL

    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.argtypes = []
    _GetCurrentProcess.restype = wintypes.HANDLE

    _GetCurrentThread = _kernel32.GetCurrentThread
    _GetCurrentThread.argtypes = []
    _GetCurrentThread.restype = wintypes.HANDLE

    _SetThreadPriority = _kernel32.SetThreadPriority
    _SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
    _SetThreadPriority.restype = wintypes.BOOL

    _QueryFullProcessImageNameW = _kernel32.QueryFullProcessImageNameW
    _QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _QueryFullProcessImageNameW.restype = wintypes.BOOL

    # IsWow64Process2 exists from Windows 10 1709; fall back to IsWow64Process before that.
    _IsWow64Process2 = getattr(_kernel32, "IsWow64Process2", None)
    if _IsWow64Process2 is not None:
        _IsWow64Process2.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.USHORT),
            ctypes.POINTER(wintypes.USHORT),
        ]
        _IsWow64Process2.restype = wintypes.BOOL

    _IsWow64Process = _kernel32.IsWow64Process
    _IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    _IsWow64Process.restype = wintypes.BOOL

    _OpenProcessToken = _advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _OpenProcessToken.restype = wintypes.BOOL

    _GetTokenInformation = _advapi32.GetTokenInformation
    _GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetTokenInformation.restype = wintypes.BOOL

    _GetSidSubAuthorityCount = _advapi32.GetSidSubAuthorityCount
    _GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    _GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)

    _GetSidSubAuthority = _advapi32.GetSidSubAuthority
    _GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    _GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

    _ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    _ConvertSidToStringSidW.restype = wintypes.BOOL

    _LookupAccountSidW = _advapi32.LookupAccountSidW
    _LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_int),
    ]
    _LookupAccountSidW.restype = wintypes.BOOL

    _GetLogicalDriveStringsW = _kernel32.GetLogicalDriveStringsW
    _GetLogicalDriveStringsW.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
    _GetLogicalDriveStringsW.restype = wintypes.DWORD

    _QueryDosDeviceW = _kernel32.QueryDosDeviceW
    _QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _QueryDosDeviceW.restype = wintypes.DWORD

    _CommandLineToArgvW = _shell32.CommandLineToArgvW
    _CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    _CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)

    _NtQueryInformationProcess = _ntdll.NtQueryInformationProcess
    _NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _NtQueryInformationProcess.restype = wintypes.LONG

    _RtlNtStatusToDosError = _ntdll.RtlNtStatusToDosError
    _RtlNtStatusToDosError.argtypes = [wintypes.LONG]
    _RtlNtStatusToDosError.restype = wintypes.ULONG

    _NtSuspendProcess = _ntdll.NtSuspendProcess
    _NtSuspendProcess.argtypes = [wintypes.HANDLE]
    _NtSuspendProcess.restype = wintypes.LONG

    _NtResumeProcess = _ntdll.NtResumeProcess
    _NtResumeProcess.argtypes = [wintypes.HANDLE]
    _NtResumeProcess.restype = wintypes.LONG

    _TerminateProcess = _kernel32.TerminateProcess
    _TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _TerminateProcess.restype = wintypes.BOOL


def _last_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def _ntstatus_error(status: int) -> OSError:
    return ctypes.WinError(int(_RtlNtStatusToDosError(ctypes.c_long(status).value)))


def _token_information(token: int, info_class: int) -> ctypes.Array[ctypes.c_char]:
    """Two-call pattern: ask for the size, allocate, then fetch.

    Variable-size classes (TokenUser, TokenIntegrityLevel) fail the sizing call with
    ``ERROR_INSUFFICIENT_BUFFER``; fixed-size classes (TokenElevation) fail it with
    ``ERROR_BAD_LENGTH``. Both report the required size.
    """
    needed = wintypes.DWORD(0)
    _GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    error = ctypes.get_last_error()
    if error not in (ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH) or needed.value == 0:
        raise ctypes.WinError(error)
    buffer = ctypes.create_string_buffer(needed.value)
    if not _GetTokenInformation(token, info_class, buffer, needed.value, ctypes.byref(needed)):
        raise _last_error()
    return buffer


def split_command_line(command_line: str) -> list[str]:
    """Split a raw Windows command line exactly as the C runtime / shell does.

    API: ``CommandLineToArgvW``. Windows passes a process ONE string, not an argv array; each
    program parses it. This API implements the standard (MSVCRT-compatible) rules.
    Note: for an empty string the API returns the *current* executable's path, so we short-circuit.
    """
    _require_windows()
    if not command_line.strip():
        return []
    count = ctypes.c_int(0)
    argv = _CommandLineToArgvW(command_line, ctypes.byref(count))
    if not argv:
        raise _last_error()
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        _LocalFree(ctypes.cast(argv, wintypes.HLOCAL))


def drive_device_map() -> dict[str, str]:
    """Map NT device names to drive letters, e.g. ``\\Device\\HarddiskVolume3`` → ``C:``.

    APIs: ``GetLogicalDriveStringsW`` + ``QueryDosDeviceW``.
    """
    _require_windows()
    buffer = ctypes.create_unicode_buffer(1024)
    length = _GetLogicalDriveStringsW(len(buffer), buffer)
    if length == 0 or length > len(buffer):
        raise _last_error()
    mapping: dict[str, str] = {}
    # The buffer holds NUL-separated roots: "C:\\\0D:\\\0\0".
    for root in ctypes.wstring_at(buffer, length).split("\x00"):
        if not root:
            continue
        letter = root.rstrip("\\")  # "C:"
        target = ctypes.create_unicode_buffer(1024)
        if _QueryDosDeviceW(letter, target, len(target)):
            mapping[target.value.lower()] = letter
    return mapping


def nt_to_win32_path(nt_path: str, devices: dict[str, str]) -> str | None:
    """Convert an NT device path to a Win32 path using ``devices`` (from :func:`drive_device_map`).

    Pure function. Returns ``None`` when no mapping applies. Paths that are not device paths
    (e.g. the bare name ``Registry``) are returned unchanged.
    """
    if not nt_path.startswith("\\"):
        return nt_path
    lowered = nt_path.lower()
    mup = "\\device\\mup\\"
    if lowered.startswith(mup):
        return "\\\\" + nt_path[len(mup) :]
    for device, letter in devices.items():
        prefix = device + "\\"
        if lowered.startswith(prefix):
            return letter + nt_path[len(device) :]
    return None


class DevicePathResolver:
    """Caches the device map; refreshes on a miss at most once per ``refresh_seconds``.

    Drive letters change rarely (USB, VHD, subst), so a bounded refresh avoids re-querying every
    snapshot for a path that is genuinely unmappable.
    """

    def __init__(self, refresh_seconds: float = 30.0) -> None:
        self._refresh_seconds = refresh_seconds
        self._devices: dict[str, str] | None = None
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def to_win32(self, nt_path: str) -> str | None:
        with self._lock:
            devices = self._devices if self._devices is not None else self._reload()
            result = nt_to_win32_path(nt_path, devices)
            if result is None and time.monotonic() - self._loaded_at > self._refresh_seconds:
                result = nt_to_win32_path(nt_path, self._reload())
            return result

    def _reload(self) -> dict[str, str]:
        self._devices = drive_device_map()
        self._loaded_at = time.monotonic()
        return self._devices


class AccountResolver:
    """Resolves SIDs to ``DOMAIN\\user`` names with a cache.

    API: ``LookupAccountSidW``. Lookups for domain SIDs can go to a domain controller and take
    seconds, so each SID is resolved once. Unmappable SIDs (deleted accounts, capability SIDs)
    fall back to the string SID ``S-1-5-…`` rather than failing.
    """

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()

    def resolve(self, sid: int) -> str:
        sid_string = self._sid_to_string(sid)
        with self._lock:
            cached = self._cache.get(sid_string)
        if cached is not None:
            return cached
        name = self._lookup(sid) or sid_string
        with self._lock:
            self._cache[sid_string] = name
        return name

    @staticmethod
    def _sid_to_string(sid: int) -> str:
        out = wintypes.LPWSTR()
        if not _ConvertSidToStringSidW(sid, ctypes.byref(out)):
            raise _last_error()
        try:
            return str(out.value)
        finally:
            _LocalFree(ctypes.cast(out, wintypes.HLOCAL))

    @staticmethod
    def _lookup(sid: int) -> str | None:
        name_len = wintypes.DWORD(256)
        domain_len = wintypes.DWORD(256)
        name = ctypes.create_unicode_buffer(name_len.value)
        domain = ctypes.create_unicode_buffer(domain_len.value)
        use = ctypes.c_int(0)
        ok = _LookupAccountSidW(
            None,
            sid,
            name,
            ctypes.byref(name_len),
            domain,
            ctypes.byref(domain_len),
            ctypes.byref(use),
        )
        if not ok:
            return None
        return f"{domain.value}\\{name.value}" if domain.value else name.value


@dataclass(frozen=True, slots=True)
class MachineInfo:
    """Result of ``IsWow64Process2``: the process image machine and the native OS machine."""

    process_machine: int
    native_machine: int


class ProcessQuery:
    """One ``PROCESS_QUERY_LIMITED_INFORMATION`` handle, reused for every static field.

    ``PROCESS_QUERY_LIMITED_INFORMATION`` (Vista+) is the least-privileged access right that
    still permits image path, command line, token and WOW64 queries. It is granted for many
    processes that deny ``PROCESS_QUERY_INFORMATION``.

    Use as a context manager; the handle is always closed.
    """

    def __init__(self, pid: int, accounts: AccountResolver) -> None:
        _require_windows()
        self.pid = pid
        self._accounts = accounts
        self._handle: int | None = None

    def __enter__(self) -> Self:
        handle = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
        if not handle:
            raise _last_error()
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._handle:
            _CloseHandle(self._handle)
            self._handle = None

    @property
    def handle(self) -> int:
        if not self._handle:
            raise RuntimeError("ProcessQuery used outside its context manager")
        return self._handle

    def image_path(self) -> str:
        """API: ``QueryFullProcessImageNameW`` (Win32 path format, e.g. ``C:\\...``)."""
        size = wintypes.DWORD(_MAX_IMAGE_PATH)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not _QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(size)):
            raise _last_error()
        return buffer.value

    def command_line(self) -> str:
        """API: ``NtQueryInformationProcess(ProcessCommandLineInformation)``.

        Returns the raw command line string. The kernel copies it out of the target's PEB, so
        this reflects what the process currently has there (a process can overwrite its own).
        """
        size = 4096
        while True:
            buffer = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG(0)
            status = (
                _NtQueryInformationProcess(
                    self.handle,
                    PROCESS_COMMAND_LINE_INFORMATION,
                    buffer,
                    size,
                    ctypes.byref(needed),
                )
                & 0xFFFFFFFF
            )
            if status in (
                STATUS_INFO_LENGTH_MISMATCH,
                STATUS_BUFFER_OVERFLOW,
                STATUS_BUFFER_TOO_SMALL,
            ):
                if needed.value <= size or needed.value > _MAX_COMMAND_LINE_BYTES:
                    raise OSError(0, "command line too large or length not reported")
                size = needed.value
                continue
            if status != 0:
                raise _ntstatus_error(status)
            header = _UnicodeString.from_buffer(buffer)
            if not header.Buffer or header.Length == 0:
                return ""
            return ctypes.wstring_at(header.Buffer, header.Length // 2)

    def _with_token(self, info_class: int) -> ctypes.Array[ctypes.c_char]:
        token = wintypes.HANDLE()
        if not _OpenProcessToken(self.handle, TOKEN_QUERY, ctypes.byref(token)):
            raise _last_error()
        try:
            return _token_information(token.value or 0, info_class)
        finally:
            _CloseHandle(token)

    def username(self) -> str:
        """APIs: ``OpenProcessToken`` → ``GetTokenInformation(TokenUser)`` →
        ``LookupAccountSidW``."""
        buffer = self._with_token(TOKEN_USER_CLASS)
        user = _SidAndAttributes.from_buffer(buffer)
        return self._accounts.resolve(user.Sid)

    def integrity_rid(self) -> int:
        """APIs: ``GetTokenInformation(TokenIntegrityLevel)`` → last sub-authority of the label SID.

        Typical RIDs: 0x0000 untrusted, 0x1000 low, 0x2000 medium, 0x3000 high, 0x4000 system.
        """
        buffer = self._with_token(TOKEN_INTEGRITY_LEVEL_CLASS)
        sid = _SidAndAttributes.from_buffer(buffer).Sid
        count = _GetSidSubAuthorityCount(sid).contents.value
        if count == 0:
            raise OSError(0, "integrity label SID has no sub-authorities")
        return int(_GetSidSubAuthority(sid, count - 1).contents.value)

    def machine(self) -> MachineInfo:
        """API: ``IsWow64Process2`` (Windows 10 1709+).

        ``process_machine`` is ``IMAGE_FILE_MACHINE_UNKNOWN`` when the process is *not* under
        WOW64, i.e. native. Limitation: x64 emulation on ARM64 is not reported by this API.
        """
        if _IsWow64Process2 is not None:
            process_machine = wintypes.USHORT(0)
            native_machine = wintypes.USHORT(0)
            if not _IsWow64Process2(
                self.handle, ctypes.byref(process_machine), ctypes.byref(native_machine)
            ):
                raise _last_error()
            return MachineInfo(process_machine.value, native_machine.value)

        wow64 = wintypes.BOOL(False)
        if not _IsWow64Process(self.handle, ctypes.byref(wow64)):
            raise _last_error()
        # Pre-1709 fallback: only x86 and x64 Windows existed in practice.
        os_is_64bit = bool(wow64) or sys.maxsize > 2**32
        native = IMAGE_FILE_MACHINE_AMD64 if os_is_64bit else IMAGE_FILE_MACHINE_I386
        process = IMAGE_FILE_MACHINE_I386 if wow64 else IMAGE_FILE_MACHINE_UNKNOWN
        return MachineInfo(process, native)


THREAD_MODE_BACKGROUND_BEGIN: Final = 0x00010000


def enter_background_mode() -> bool:
    """Put the *calling thread* into background processing mode. Returns ``True`` on success.

    API: ``SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)``. Windows lowers
    the thread's CPU scheduling priority **and** its I/O and memory priority, so bulk work such as
    hashing executables yields to foreground applications. No privileges are required; it only
    affects the current thread. Failure (e.g. already in background mode) is harmless.
    """
    if not is_windows():
        return False
    return bool(_SetThreadPriority(_GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN))


def _open_for(pid: int, access: int) -> int:
    handle: int | None = _OpenProcess(access, False, pid)
    if not handle:
        raise _last_error()
    return int(handle)


def suspend_process(pid: int) -> None:
    """Suspend all threads of a process.

    APIs: ``OpenProcess(PROCESS_SUSPEND_RESUME)`` → ``ntdll!NtSuspendProcess``. Suspending freezes
    the process without destroying it — reversible with :func:`resume_process` — which is the
    safe first response to suspicious activity. Requires rights over the target: a standard user
    can suspend only their own processes; PPL processes cannot be suspended even by an admin.
    """
    _require_windows()
    handle = _open_for(pid, PROCESS_SUSPEND_RESUME)
    try:
        status = int(_NtSuspendProcess(handle)) & 0xFFFFFFFF
        if status != 0:
            raise _ntstatus_error(status)
    finally:
        _CloseHandle(handle)


def resume_process(pid: int) -> None:
    """Resume a suspended process. APIs: ``OpenProcess`` → ``ntdll!NtResumeProcess``."""
    _require_windows()
    handle = _open_for(pid, PROCESS_SUSPEND_RESUME)
    try:
        status = int(_NtResumeProcess(handle)) & 0xFFFFFFFF
        if status != 0:
            raise _ntstatus_error(status)
    finally:
        _CloseHandle(handle)


def terminate_process(pid: int, exit_code: int = 1) -> None:
    """Terminate a process.

    APIs: ``OpenProcess(PROCESS_TERMINATE)`` → ``TerminateProcess``. This is abrupt and
    irreversible; WinSentinel only reaches it after an explicit, confirmed user request and never
    for a protected system process.
    """
    _require_windows()
    handle = _open_for(pid, PROCESS_TERMINATE)
    try:
        if not _TerminateProcess(handle, exit_code):
            raise _last_error()
    finally:
        _CloseHandle(handle)


def is_current_process_elevated() -> bool:
    """Whether this process runs with an elevated (UAC "Run as administrator") token.

    API: ``GetTokenInformation(TokenElevation)`` on our own token. More accurate than the
    deprecated ``IsUserAnAdmin``: an administrator running *unelevated* under UAC holds a
    filtered token and is correctly reported as not elevated.
    """
    _require_windows()
    token = wintypes.HANDLE()
    if not _OpenProcessToken(_GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise _last_error()
    try:
        buffer = _token_information(token.value or 0, TOKEN_ELEVATION_CLASS)
    finally:
        _CloseHandle(token)
    return bool(wintypes.DWORD.from_buffer(buffer).value)


@dataclass(frozen=True, slots=True)
class WindowsVersion:
    major: int
    minor: int
    build: int
    edition: str
    product: str

    @property
    def is_supported(self) -> bool:
        return self.major == 10 and self.build >= WINDOWS_10_FIRST_BUILD


def get_windows_version() -> WindowsVersion:
    """Detect the Windows version.

    Windows 11 still reports major version 10; the build number (22000+) is the only reliable
    discriminator.
    """
    _require_windows()
    info = sys.getwindowsversion()
    product = "Windows 11" if info.build >= WINDOWS_11_FIRST_BUILD else f"Windows {info.major}"
    return WindowsVersion(
        major=info.major,
        minor=info.minor,
        build=info.build,
        edition=platform.win32_edition() or "unknown",
        product=product,
    )
