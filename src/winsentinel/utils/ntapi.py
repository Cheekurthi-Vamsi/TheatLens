"""Bulk process enumeration via ``NtQuerySystemInformation(SystemProcessInformation)``.

What Windows API is used?
    ``ntdll!NtQuerySystemInformation`` with information class 5. The kernel fills one buffer
    with a linked list of ``SYSTEM_PROCESS_INFORMATION`` records, each followed by an array of
    ``SYSTEM_THREAD_INFORMATION`` records. Task Manager, Process Explorer and psutil's internal
    fallbacks all rely on it.

Why is it needed?
    It returns PID, parent PID, image name, creation time, session, thread/handle counts,
    memory counters, CPU times **and** per-thread wait state for *every* process in one system
    call, without opening a single process handle. Profiling showed per-process psutil getters
    re-query this list on each call (O(n²)); one bulk call per snapshot is O(n) and takes a few
    milliseconds.

What permissions does it require?
    None. Any user can enumerate all processes this way, including protected ones.

Limitations
    * The structure is documented in ``winternl.h`` only partially (many fields are "Reserved"),
      but the x64 layout has been stable since Windows Vista and is relied upon by the whole
      ecosystem. Structure sizes are asserted in the test suite.
    * Image name is the file name only (no directory).
    * Snapshot semantics: a process can exit immediately after the call returns.

What happens if it fails?
    Raises ``OSError`` (translated from the NTSTATUS). The collector converts this into
    ``CollectorUnavailableError`` — a genuine collector-wide failure.

Alternatives
    ``CreateToolhelp32Snapshot`` (no memory/CPU counters), ``EnumProcesses`` (PIDs only),
    WMI ``Win32_Process`` (much slower), ETW (event-driven, needs admin).
"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from typing import Final

from winsentinel.errors import PlatformNotSupportedError
from winsentinel.utils.time import FILETIME_EPOCH_OFFSET, HUNDRED_NS_PER_SECOND

__all__ = ["FILETIME_EPOCH_OFFSET", "HUNDRED_NS_PER_SECOND"]  # re-exported for existing callers

SYSTEM_PROCESS_INFORMATION_CLASS: Final = 5
SYSTEM_PROCESS_ID_INFORMATION_CLASS: Final = 88
STATUS_SUCCESS: Final = 0
STATUS_INFO_LENGTH_MISMATCH: Final = 0xC0000004
STATUS_BUFFER_TOO_SMALL: Final = 0xC0000023

# KTHREAD_STATE / KWAIT_REASON values
THREAD_STATE_WAITING: Final = 5
WAIT_REASON_SUSPENDED: Final = 5

_INITIAL_BUFFER: Final = 512 * 1024
_BUFFER_HEADROOM: Final = 64 * 1024
_MAX_BUFFER: Final = 256 * 1024 * 1024


class UnicodeString(ctypes.Structure):
    _fields_ = (
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    )


class SystemProcessInformation(ctypes.Structure):
    _fields_ = (
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", UnicodeString),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
        ("UniqueProcessKey", ctypes.c_size_t),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", wintypes.ULONG),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
        ("ReadOperationCount", ctypes.c_longlong),
        ("WriteOperationCount", ctypes.c_longlong),
        ("OtherOperationCount", ctypes.c_longlong),
        ("ReadTransferCount", ctypes.c_longlong),
        ("WriteTransferCount", ctypes.c_longlong),
        ("OtherTransferCount", ctypes.c_longlong),
    )


class ClientId(ctypes.Structure):
    _fields_ = (("UniqueProcess", ctypes.c_void_p), ("UniqueThread", ctypes.c_void_p))


class SystemThreadInformation(ctypes.Structure):
    _fields_ = (
        ("KernelTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("CreateTime", ctypes.c_longlong),
        ("WaitTime", wintypes.ULONG),
        ("StartAddress", ctypes.c_void_p),
        ("ClientId", ClientId),
        ("Priority", wintypes.LONG),
        ("BasePriority", wintypes.LONG),
        ("ContextSwitches", wintypes.ULONG),
        ("ThreadState", wintypes.ULONG),
        ("WaitReason", wintypes.ULONG),
    )


@dataclass(frozen=True, slots=True)
class SystemProcessEntry:
    """One process as reported by ``SystemProcessInformation``."""

    pid: int
    ppid: int
    image_name: str
    create_time_filetime: int  # 100ns since 1601-01-01 UTC; 0 for pseudo processes
    session_id: int
    num_threads: int
    handle_count: int
    working_set: int
    private_bytes: int
    cpu_time_100ns: int  # user + kernel
    all_threads_suspended: bool

    @property
    def create_time_epoch(self) -> float:
        """Creation time as Unix epoch seconds; ``0.0`` when unavailable."""
        if self.create_time_filetime <= FILETIME_EPOCH_OFFSET:
            return 0.0
        return (self.create_time_filetime - FILETIME_EPOCH_OFFSET) / HUNDRED_NS_PER_SECOND


if sys.platform == "win32":
    _ntdll = ctypes.WinDLL("ntdll")
    _NtQuerySystemInformation = _ntdll.NtQuerySystemInformation
    _NtQuerySystemInformation.argtypes = [
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _NtQuerySystemInformation.restype = wintypes.LONG

    _RtlNtStatusToDosError = _ntdll.RtlNtStatusToDosError
    _RtlNtStatusToDosError.argtypes = [wintypes.LONG]
    _RtlNtStatusToDosError.restype = wintypes.ULONG


def ntstatus_error(status: int) -> OSError:
    """Translate an NTSTATUS into an ``OSError`` carrying the equivalent Win32 error code."""
    win32 = int(_RtlNtStatusToDosError(ctypes.c_long(status).value))
    return ctypes.WinError(win32, f"NTSTATUS 0x{status & 0xFFFFFFFF:08X}")


_IDLE_PROCESS_NAME: Final = "System Idle Process"
_PROCESS_HEADER_SIZE: Final = ctypes.sizeof(SystemProcessInformation)
_THREAD_SIZE: Final = ctypes.sizeof(SystemThreadInformation)


def _threads_all_suspended(address: int, count: int) -> bool:
    if count == 0:
        return False
    threads = (SystemThreadInformation * count).from_address(address + _PROCESS_HEADER_SIZE)
    return all(
        t.ThreadState == THREAD_STATE_WAITING and t.WaitReason == WAIT_REASON_SUSPENDED
        for t in threads
    )


def parse_process_buffer(
    buffer: ctypes.Array[ctypes.c_char], used: int
) -> list[SystemProcessEntry]:
    """Walk the ``NextEntryOffset`` linked list inside ``buffer``.

    Offsets are validated against the bytes actually written, so a malformed buffer can never
    make us read outside our own allocation.
    """
    base = ctypes.addressof(buffer)
    entries: list[SystemProcessEntry] = []
    offset = 0
    while True:
        if offset + _PROCESS_HEADER_SIZE > used:
            raise OSError(0, "SystemProcessInformation buffer is truncated")
        info = SystemProcessInformation.from_address(base + offset)
        if offset + _PROCESS_HEADER_SIZE + info.NumberOfThreads * _THREAD_SIZE > used:
            raise OSError(0, "SystemProcessInformation thread array is truncated")

        pid = int(info.UniqueProcessId or 0)
        name_chars = info.ImageName.Length // 2
        if info.ImageName.Buffer and name_chars:
            name = ctypes.wstring_at(info.ImageName.Buffer, name_chars)
        else:
            name = _IDLE_PROCESS_NAME if pid == 0 else ""
        entries.append(
            SystemProcessEntry(
                pid=pid,
                ppid=int(info.InheritedFromUniqueProcessId or 0),
                image_name=name,
                create_time_filetime=int(info.CreateTime),
                session_id=int(info.SessionId),
                num_threads=int(info.NumberOfThreads),
                handle_count=int(info.HandleCount),
                working_set=int(info.WorkingSetSize),
                private_bytes=int(info.PrivatePageCount),
                cpu_time_100ns=int(info.UserTime) + int(info.KernelTime),
                all_threads_suspended=_threads_all_suspended(base + offset, info.NumberOfThreads),
            )
        )
        if info.NextEntryOffset == 0:
            return entries
        offset += info.NextEntryOffset


class _SystemProcessIdInformation(ctypes.Structure):
    _fields_ = (("ProcessId", ctypes.c_void_p), ("ImageName", UnicodeString))


_IMAGE_NAME_INITIAL_CHARS: Final = 1024
_IMAGE_NAME_MAX_BYTES: Final = 0xFFFE  # UNICODE_STRING lengths are USHORT byte counts


def query_image_name_by_pid(pid: int) -> str:
    """Return a process's image path in NT device form, **without opening the process**.

    API: ``NtQuerySystemInformation(SystemProcessIdInformation)``. The kernel reads the name
    from the process object's image file, so it works as a standard user for SYSTEM and other
    users' processes (not for the minimal *Registry*/*Memory Compression* processes, which have
    no image file and return a bare name). Unlike the command line, user mode cannot tamper
    with this value.

    Returns e.g. ``\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe``; convert with
    :class:`winsentinel.utils.windows.DevicePathResolver`.
    """
    if sys.platform != "win32":
        raise PlatformNotSupportedError("NtQuerySystemInformation requires Windows.")
    capacity_bytes = _IMAGE_NAME_INITIAL_CHARS * 2
    for _ in range(2):
        buffer = ctypes.create_unicode_buffer(capacity_bytes // 2)
        info = _SystemProcessIdInformation()
        info.ProcessId = pid
        info.ImageName.Length = 0
        info.ImageName.MaximumLength = capacity_bytes
        info.ImageName.Buffer = ctypes.addressof(buffer)
        status = (
            _NtQuerySystemInformation(
                SYSTEM_PROCESS_ID_INFORMATION_CLASS,
                ctypes.byref(info),
                ctypes.sizeof(info),
                None,
            )
            & 0xFFFFFFFF
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            # The kernel reports the required byte count in MaximumLength.
            capacity_bytes = min(
                _IMAGE_NAME_MAX_BYTES, max(capacity_bytes, info.ImageName.MaximumLength)
            )
            continue
        if status != STATUS_SUCCESS:
            raise ntstatus_error(status)
        return ctypes.wstring_at(buffer, info.ImageName.Length // 2)
    raise OSError(0, "image name did not fit the maximum UNICODE_STRING size")


class SystemProcessQuery:
    """Reusable querier; keeps its buffer between calls to avoid re-allocating each snapshot."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformNotSupportedError("NtQuerySystemInformation requires Windows.")
        self._size = _INITIAL_BUFFER
        self._buffer = ctypes.create_string_buffer(self._size)
        self._lock = threading.Lock()

    def query(self) -> list[SystemProcessEntry]:
        with self._lock:
            while True:
                needed = wintypes.ULONG(0)
                status = (
                    _NtQuerySystemInformation(
                        SYSTEM_PROCESS_INFORMATION_CLASS,
                        self._buffer,
                        self._size,
                        ctypes.byref(needed),
                    )
                    & 0xFFFFFFFF
                )
                if status in (STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL):
                    # The process list can grow between calls; leave headroom.
                    new_size = max(self._size * 2, needed.value + _BUFFER_HEADROOM)
                    if new_size > _MAX_BUFFER:
                        raise OSError(0, f"process list exceeds {_MAX_BUFFER} bytes")
                    self._size = new_size
                    self._buffer = ctypes.create_string_buffer(self._size)
                    continue
                if status != STATUS_SUCCESS:
                    raise ntstatus_error(status)
                return parse_process_buffer(self._buffer, needed.value or self._size)
