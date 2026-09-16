"""Test doubles for the OS layer. No Windows APIs are touched by anything in this module."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from threatlens.core.models import (
    AddressFamily,
    ConnectionState,
    Direction,
    IntegrityLevel,
    NetworkConnection,
    ProcessInfo,
    SignatureInfo,
    SignatureSource,
    SignatureStatus,
    TransportProtocol,
)
from threatlens.utils import windows
from threatlens.utils.iphlpapi import RawSocketEntry
from threatlens.utils.ntapi import FILETIME_EPOCH_OFFSET, HUNDRED_NS_PER_SECOND, SystemProcessEntry

BASE_TIME = datetime(2026, 9, 15, 11, 0, 0, tzinfo=UTC)


def filetime(ts: datetime) -> int:
    return int(ts.timestamp() * HUNDRED_NS_PER_SECOND) + FILETIME_EPOCH_OFFSET


def entry(
    pid: int,
    ppid: int = 4,
    name: str = "app.exe",
    *,
    created: datetime | None = None,
    cpu_seconds: float = 0.0,
    suspended: bool = False,
    working_set: int = 10_000_000,
) -> SystemProcessEntry:
    created = created or BASE_TIME
    return SystemProcessEntry(
        pid=pid,
        ppid=ppid,
        image_name=name,
        create_time_filetime=0 if pid in (0, 4) else filetime(created),
        session_id=1,
        num_threads=4,
        handle_count=100,
        working_set=working_set,
        private_bytes=working_set // 2,
        cpu_time_100ns=int(cpu_seconds * HUNDRED_NS_PER_SECOND),
        all_threads_suspended=suspended,
    )


class FakeSource:
    """Returns successive entry lists on each ``query()``; the last one repeats."""

    def __init__(
        self, *snapshots: Sequence[SystemProcessEntry], error: OSError | None = None
    ) -> None:
        self._snapshots = [list(s) for s in snapshots] or [[]]
        self._error = error
        self.calls = 0

    def query(self) -> list[SystemProcessEntry]:
        self.calls += 1
        if self._error is not None:
            raise self._error
        index = min(self.calls - 1, len(self._snapshots) - 1)
        return self._snapshots[index]


def access_denied() -> OSError:
    error = OSError(13, "Access is denied")
    error.winerror = windows.ERROR_ACCESS_DENIED  # type: ignore[attr-defined]
    return error


def invalid_parameter() -> OSError:
    error = OSError(22, "The parameter is incorrect")
    error.winerror = windows.ERROR_INVALID_PARAMETER  # type: ignore[attr-defined]
    return error


@dataclass
class FakeDetails:
    exe: str | Exception = r"C:\Program Files\App\app.exe"
    argv: list[str] | Exception = field(default_factory=lambda: [r"C:\Program Files\App\app.exe"])
    username: str | Exception = r"HOST\alice"
    integrity_rid: int | Exception = 0x2000
    machine: windows.MachineInfo | Exception = field(
        default_factory=lambda: windows.MachineInfo(0, windows.IMAGE_FILE_MACHINE_AMD64)
    )
    open_error: Exception | None = None
    fallback_exe: str | Exception = field(default_factory=access_denied)


def _value(value: Any) -> Any:
    if isinstance(value, Exception):
        raise value
    return value


class _FakeReader:
    def __init__(self, details: FakeDetails) -> None:
        self._d = details

    def image_path(self) -> str:
        return str(_value(self._d.exe))

    def argv(self) -> list[str]:
        return list(_value(self._d.argv))

    def username(self) -> str:
        return str(_value(self._d.username))

    def integrity_rid(self) -> int:
        return int(_value(self._d.integrity_rid))

    def machine(self) -> windows.MachineInfo:
        result: windows.MachineInfo = _value(self._d.machine)
        return result


class FakeInspector:
    def __init__(self, details: dict[int, FakeDetails] | None = None) -> None:
        self.details = details or {}
        self.open_calls: list[int] = []

    def _for(self, pid: int) -> FakeDetails:
        return self.details.get(pid, FakeDetails())

    @contextmanager
    def open(self, pid: int) -> Iterator[_FakeReader]:
        self.open_calls.append(pid)
        details = self._for(pid)
        if details.open_error is not None:
            raise details.open_error
        yield _FakeReader(details)

    def image_path_by_pid(self, pid: int) -> str:
        return str(_value(self._for(pid).fallback_exe))


class FakeClock:
    """Wall clock + monotonic clock advanced manually."""

    def __init__(self, start: datetime = BASE_TIME + timedelta(minutes=5)) -> None:
        self.wall = start
        self.mono = 1000.0

    def advance(self, seconds: float) -> None:
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono


def process(
    pid: int,
    ppid: int | None = 4,
    name: str = "app.exe",
    *,
    created: datetime | None = None,
    suspended: bool | None = False,
    **overrides: Any,
) -> ProcessInfo:
    values: dict[str, Any] = {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": rf"C:\Program Files\App\{name}",
        "create_time": created or BASE_TIME,
        "integrity_level": IntegrityLevel.MEDIUM,
        "suspended": suspended,
        "collected_at": BASE_TIME + timedelta(minutes=5),
    }
    values.update(overrides)
    return ProcessInfo(**values)


def minutes(n: float) -> datetime:
    return BASE_TIME + timedelta(minutes=n)


Factory = Callable[..., ProcessInfo]


# --------------------------------------------------------------------------------------------
# Network fakes
# --------------------------------------------------------------------------------------------

TCP_STATES = {"LISTEN": 2, "SYN_SENT": 3, "ESTABLISHED": 5, "CLOSE_WAIT": 8, "TIME_WAIT": 11}


def socket_entry(
    pid: int,
    local: str = "10.0.0.5",
    local_port: int = 50000,
    remote: str | None = "93.184.216.34",
    remote_port: int | None = 443,
    *,
    protocol: str = "TCP",
    state: str = "ESTABLISHED",
    created: datetime | None = None,
) -> RawSocketEntry:
    is_listen = protocol == "TCP" and state == "LISTEN"
    return RawSocketEntry(
        protocol=protocol,
        ipv6=":" in local,
        local_address=local,
        local_port=local_port,
        remote_address=None if (is_listen or protocol == "UDP") else remote,
        remote_port=None if (is_listen or protocol == "UDP") else remote_port,
        state=TCP_STATES[state] if protocol == "TCP" else 0,
        pid=pid,
        create_filetime=filetime(created or BASE_TIME + timedelta(minutes=1)),
        row_bytes=b"",
    )


class FakeSocketSource:
    def __init__(
        self,
        *snapshots: Sequence[RawSocketEntry],
        failing_tables: set[tuple[str, str]] | None = None,
        owners: dict[int, str | Exception] | None = None,
    ) -> None:
        self._snapshots = [list(s) for s in snapshots] or [[]]
        self._failing = failing_tables or set()
        self._owners = owners or {}
        self.calls = 0
        self.owner_calls = 0

    def query(self, protocol: Any, family: Any) -> list[RawSocketEntry]:
        if (protocol.value, family.value) in self._failing:
            raise OSError(50, "table unavailable")
        if (protocol.value, family.value) == ("TCP", "IPV4"):
            self.calls += 1
        rows = self._snapshots[min(max(self.calls - 1, 0), len(self._snapshots) - 1)]
        want_v6 = family.value == "IPV6"
        return [r for r in rows if r.protocol == protocol.value and r.ipv6 == want_v6]

    def owner_module(self, entry: RawSocketEntry) -> str:
        self.owner_calls += 1
        value = self._owners.get(entry.pid, "")
        if isinstance(value, Exception):
            raise value
        return value


class FakeEnricher:
    """Deterministic stand-in for ProcessEnricher: no file I/O."""

    def __init__(self, signatures: dict[str, SignatureInfo] | None = None) -> None:
        self.signatures = signatures or {}
        self.calls = 0

    def enrich(self, info: ProcessInfo) -> ProcessInfo:
        self.calls += 1
        signature = self.signatures.get(
            info.name,
            SignatureInfo(
                status=SignatureStatus.VALID,
                source=SignatureSource.EMBEDDED,
                signer="Test Publisher",
            ),
        )
        return info.model_copy(update={"sha256": "ab" * 32, "signature": signature})


def connection(
    pid: int,
    remote: str | None = "93.184.216.34",
    remote_port: int | None = 443,
    *,
    local: str = "10.0.0.5",
    local_port: int = 50000,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    protocol: TransportProtocol = TransportProtocol.TCP,
    direction: Direction = Direction.OUTBOUND,
    created: datetime | None = None,
    owner_module: str | None = None,
) -> NetworkConnection:
    from threatlens.utils.networking import classify_address

    return NetworkConnection(
        protocol=protocol,
        family=AddressFamily.IPV6 if ":" in local else AddressFamily.IPV4,
        local_address=local,
        local_port=local_port,
        remote_address=remote,
        remote_port=remote_port,
        state=state,
        pid=pid,
        created_at=created or BASE_TIME + timedelta(minutes=1),
        owner_module=owner_module,
        direction=direction,
        local_scope=classify_address(local),
        remote_scope=None if remote is None else classify_address(remote),
        observed_at=BASE_TIME + timedelta(minutes=5),
    )
