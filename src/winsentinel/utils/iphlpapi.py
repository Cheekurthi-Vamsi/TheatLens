"""TCP/UDP socket tables with owning PID, creation time and owner module.

What Windows API is used?
    ``iphlpapi!GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_ALL)`` and
    ``iphlpapi!GetExtendedUdpTable(UDP_TABLE_OWNER_MODULE)`` for IPv4 and IPv6, plus
    ``GetOwnerModuleFrom{Tcp,Tcp6,Udp,Udp6}Entry`` for the owning module / service name.

Why is it needed?
    These tables are how Windows exposes **which process owns each socket** — the foundation of
    process ↔ network correlation. The ``OWNER_MODULE`` table class (rather than the more common
    ``OWNER_PID``) adds two things psutil discards:

    * ``liCreateTimestamp`` — when the socket was created. Detection can measure "connected N
      seconds after process start" exactly, regardless of polling interval, and correlation can
      reject a socket that is *older* than the process now holding its PID (PID reuse).
    * the owner module — for ``svchost.exe`` this is the **service name** (e.g. ``Dnscache``),
      which tells you which of the dozens of svchost instances' services made a connection.

What permissions does it require?
    Tables: none. Owner module lookup: works for most sockets as a standard user; fails with
    ``ERROR_ACCESS_DENIED`` for some protected/system owners (measured 4 of 37 on a test machine).

Limitations
    * Snapshot semantics: connections that open and close between polls are never seen.
    * UDP is connectionless: rows carry only the local endpoint.
    * Kernel-mode sockets (SMB, ``http.sys``) are owned by PID 4 (*System*).
    * ``TIME_WAIT`` rows may report PID 0 once the owner has released the socket.

What happens if it fails?
    Each table is queried independently; a failing table raises ``OSError`` which the collector
    records while still returning the other tables.

Alternatives
    psutil ``net_connections`` (same tables, ``OWNER_PID`` class: no timestamps or services),
    ``netstat -ano`` (text parsing), ETW ``Microsoft-Windows-Kernel-Network`` (event-driven, sees
    short-lived connections, requires admin), Windows Filtering Platform auditing (admin).
"""

from __future__ import annotations

import ctypes
import functools
import ipaddress
import socket
import struct
import sys
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Final

from winsentinel.errors import PlatformNotSupportedError

AF_INET: Final = 2
AF_INET6: Final = 23
TCP_TABLE_OWNER_MODULE_ALL: Final = 8
UDP_TABLE_OWNER_MODULE: Final = 2
TCPIP_OWNER_MODULE_INFO_BASIC: Final = 0
TCPIP_OWNING_MODULE_SIZE: Final = 16
ERROR_INSUFFICIENT_BUFFER: Final = 122
NO_ERROR: Final = 0

_MAX_ATTEMPTS: Final = 5
_BUFFER_HEADROOM: Final = 16 * 1024
_OWNER_BUFFER_BYTES: Final = 4096

# MIB_TCP_STATE (tcpmib.h)
TCP_STATE_NAMES: Final[dict[int, str]] = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}
TCP_STATE_LISTEN: Final = 2


class TcpRowOwnerModule(ctypes.Structure):
    _fields_ = (
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
        ("liCreateTimestamp", ctypes.c_longlong),
        ("OwningModuleInfo", ctypes.c_ulonglong * TCPIP_OWNING_MODULE_SIZE),
    )


class Tcp6RowOwnerModule(ctypes.Structure):
    _fields_ = (
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
        ("liCreateTimestamp", ctypes.c_longlong),
        ("OwningModuleInfo", ctypes.c_ulonglong * TCPIP_OWNING_MODULE_SIZE),
    )


class UdpRowOwnerModule(ctypes.Structure):
    _fields_ = (
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
        ("liCreateTimestamp", ctypes.c_longlong),
        ("dwFlags", ctypes.c_int),
        ("OwningModuleInfo", ctypes.c_ulonglong * TCPIP_OWNING_MODULE_SIZE),
    )


class Udp6RowOwnerModule(ctypes.Structure):
    _fields_ = (
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
        ("liCreateTimestamp", ctypes.c_longlong),
        ("dwFlags", ctypes.c_int),
        ("OwningModuleInfo", ctypes.c_ulonglong * TCPIP_OWNING_MODULE_SIZE),
    )


RowType = (
    type[TcpRowOwnerModule]
    | type[Tcp6RowOwnerModule]
    | type[UdpRowOwnerModule]
    | type[Udp6RowOwnerModule]
)


@functools.cache
def _table_type(row: RowType) -> type[ctypes.Structure]:
    """``MIB_*TABLE_OWNER_MODULE``: a DWORD count followed by rows at the row's alignment.

    Building the type lets ctypes compute the padding between the count and the first row
    (8 bytes on x64, because rows contain 64-bit fields) instead of hard-coding it.
    """
    fields = (("dwNumEntries", wintypes.DWORD), ("table", row * 1))
    return type(f"{row.__name__}Table", (ctypes.Structure,), {"_fields_": fields})


class _OwnerModuleBasicInfo(ctypes.Structure):
    _fields_ = (("pModuleName", wintypes.LPWSTR), ("pModulePath", wintypes.LPWSTR))


@dataclass(frozen=True, slots=True)
class RawSocketEntry:
    """A decoded table row. ``row_bytes`` keeps the original row for owner-module lookups."""

    protocol: str  # "TCP" | "UDP"
    ipv6: bool
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    state: int  # MIB_TCP_STATE; 0 for UDP
    pid: int
    create_filetime: int
    row_bytes: bytes

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port,
            self.pid,
            self.create_filetime,
        )


def network_port(value: int) -> int:
    """Ports are stored in network byte order in the low 16 bits of a DWORD."""
    low = value & 0xFFFF
    return ((low & 0xFF) << 8) | (low >> 8)


def ipv4_from_dword(value: int) -> str:
    """The DWORD holds the address bytes in network order; on little-endian x86/ARM read as-is."""
    return socket.inet_ntoa(struct.pack("<I", value))


def ipv6_from_bytes(raw: ctypes.Array[ctypes.c_ubyte]) -> str:
    return str(ipaddress.IPv6Address(bytes(raw)))


if sys.platform == "win32":
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _TABLE_ARGTYPES: list[Any] = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    _GetExtendedTcpTable = _iphlpapi.GetExtendedTcpTable
    _GetExtendedTcpTable.argtypes = _TABLE_ARGTYPES
    _GetExtendedTcpTable.restype = wintypes.DWORD
    _GetExtendedUdpTable = _iphlpapi.GetExtendedUdpTable
    _GetExtendedUdpTable.argtypes = _TABLE_ARGTYPES
    _GetExtendedUdpTable.restype = wintypes.DWORD

    def _owner_fn(name: str, row: RowType) -> Any:
        fn = getattr(_iphlpapi, name)
        fn.argtypes = [
            ctypes.POINTER(row),
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        ]
        fn.restype = wintypes.DWORD
        return fn

    _OWNER_FUNCTIONS = {
        ("TCP", False): (
            _owner_fn("GetOwnerModuleFromTcpEntry", TcpRowOwnerModule),
            TcpRowOwnerModule,
        ),
        ("TCP", True): (
            _owner_fn("GetOwnerModuleFromTcp6Entry", Tcp6RowOwnerModule),
            Tcp6RowOwnerModule,
        ),
        ("UDP", False): (
            _owner_fn("GetOwnerModuleFromUdpEntry", UdpRowOwnerModule),
            UdpRowOwnerModule,
        ),
        ("UDP", True): (
            _owner_fn("GetOwnerModuleFromUdp6Entry", Udp6RowOwnerModule),
            Udp6RowOwnerModule,
        ),
    }


def _fetch_table(protocol: str, ipv6: bool) -> tuple[ctypes.Array[ctypes.c_char], int]:
    """Two-call buffer pattern; the table can grow between calls, so retry a few times."""
    function = _GetExtendedTcpTable if protocol == "TCP" else _GetExtendedUdpTable
    table_class = TCP_TABLE_OWNER_MODULE_ALL if protocol == "TCP" else UDP_TABLE_OWNER_MODULE
    family = AF_INET6 if ipv6 else AF_INET
    size = wintypes.DWORD(0)
    function(None, ctypes.byref(size), False, family, table_class, 0)
    for _ in range(_MAX_ATTEMPTS):
        capacity = size.value + _BUFFER_HEADROOM
        buffer = ctypes.create_string_buffer(capacity)
        size = wintypes.DWORD(capacity)
        result = function(buffer, ctypes.byref(size), False, family, table_class, 0)
        if result == NO_ERROR:
            return buffer, size.value
        if result != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(result)
    raise OSError(0, f"{protocol} table kept growing; gave up after {_MAX_ATTEMPTS} attempts")


def _row_type(protocol: str, ipv6: bool) -> RowType:
    if protocol == "TCP":
        return Tcp6RowOwnerModule if ipv6 else TcpRowOwnerModule
    return Udp6RowOwnerModule if ipv6 else UdpRowOwnerModule


def parse_table(
    buffer: ctypes.Array[ctypes.c_char], used: int, protocol: str, ipv6: bool
) -> list[RawSocketEntry]:
    """Decode a table buffer. Row count is bounds-checked against the bytes actually written."""
    row_type = _row_type(protocol, ipv6)
    table_type = _table_type(row_type)
    offset = table_type.table.offset
    row_size = ctypes.sizeof(row_type)
    count = wintypes.DWORD.from_buffer(buffer).value
    if offset + count * row_size > min(used, len(buffer)):
        raise OSError(0, f"{protocol} table reports {count} rows but buffer is too small")
    rows = (row_type * count).from_buffer(buffer, offset)
    return [_decode(row, protocol, ipv6) for row in rows]


def _decode(row: ctypes.Structure, protocol: str, ipv6: bool) -> RawSocketEntry:
    r = row
    local = ipv6_from_bytes(r.ucLocalAddr) if ipv6 else ipv4_from_dword(r.dwLocalAddr)
    remote: str | None = None
    remote_port: int | None = None
    state = 0
    if protocol == "TCP":
        state = int(r.dwState)
        if state != TCP_STATE_LISTEN:
            remote = ipv6_from_bytes(r.ucRemoteAddr) if ipv6 else ipv4_from_dword(r.dwRemoteAddr)
            remote_port = network_port(r.dwRemotePort)
    return RawSocketEntry(
        protocol=protocol,
        ipv6=ipv6,
        local_address=local,
        local_port=network_port(r.dwLocalPort),
        remote_address=remote,
        remote_port=remote_port,
        state=state,
        pid=int(r.dwOwningPid),
        create_filetime=int(r.liCreateTimestamp),
        row_bytes=bytes(row),
    )


def query_socket_table(protocol: str, ipv6: bool) -> list[RawSocketEntry]:
    """Return all rows of one table. Raises ``OSError``."""
    if sys.platform != "win32":
        raise PlatformNotSupportedError("Socket tables require Windows.")
    buffer, used = _fetch_table(protocol, ipv6)
    return parse_table(buffer, used, protocol, ipv6)


def owner_module_name(entry: RawSocketEntry) -> str:
    """Owning module name for a socket (service name for services). Raises ``OSError``.

    API: ``GetOwnerModuleFrom*Entry(TCPIP_OWNER_MODULE_INFO_BASIC)``. The returned structure's
    string pointers point *into* our buffer, so it is read before the buffer is released.
    """
    if sys.platform != "win32":
        raise PlatformNotSupportedError("Owner module lookup requires Windows.")
    function, row_type = _OWNER_FUNCTIONS[(entry.protocol, entry.ipv6)]
    row = row_type.from_buffer_copy(entry.row_bytes)
    size = wintypes.DWORD(_OWNER_BUFFER_BYTES)
    for _ in range(2):
        buffer = ctypes.create_string_buffer(size.value)
        result = function(
            ctypes.byref(row), TCPIP_OWNER_MODULE_INFO_BASIC, buffer, ctypes.byref(size)
        )
        if result == NO_ERROR:
            info = _OwnerModuleBasicInfo.from_buffer(buffer)
            return str(info.pModuleName or "")
        if result != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(result)
    raise OSError(0, "owner module buffer size negotiation failed")
