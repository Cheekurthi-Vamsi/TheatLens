"""Network domain models (Phase 2)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, computed_field

from winsentinel.core.models.common import Frozen, Pid, Port


class TransportProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"


class AddressFamily(StrEnum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"


class ConnectionState(StrEnum):
    """TCP states from ``MIB_TCP_STATE``; UDP endpoints are ``NONE`` (connectionless)."""

    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    DELETE_TCB = "DELETE_TCB"
    NONE = "NONE"


class Direction(StrEnum):
    """Inferred, not observed: the socket table does not record who initiated a connection."""

    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    LISTENING = "LISTENING"
    BOUND = "BOUND"  # UDP endpoint
    UNKNOWN = "UNKNOWN"


class AddressScope(StrEnum):
    UNSPECIFIED = "UNSPECIFIED"  # 0.0.0.0 / :: — all interfaces
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"


class Attribution(StrEnum):
    """How confidently a socket's owning PID maps to a known process instance."""

    ATTRIBUTED = "ATTRIBUTED"
    KERNEL = "KERNEL"  # PID 4: kernel-mode socket (SMB, http.sys) — the real app is not visible
    UNATTRIBUTED = "UNATTRIBUTED"  # PID 0 or process no longer known
    PID_REUSE_SUSPECTED = "PID_REUSE_SUSPECTED"  # socket is older than the process holding the PID


class NetworkConnection(Frozen):
    """One row of the TCP/UDP owner tables, enriched with inferred direction and scope."""

    protocol: TransportProtocol
    family: AddressFamily
    local_address: str
    local_port: Port
    remote_address: str | None = None
    remote_port: Port | None = None
    state: ConnectionState
    pid: Pid
    created_at: AwareDatetime | None = None
    owner_module: str | None = None
    direction: Direction = Direction.UNKNOWN
    local_scope: AddressScope
    remote_scope: AddressScope | None = None
    observed_at: AwareDatetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def connection_key(self) -> str:
        """Identity across snapshots: endpoints + owner + socket creation time.

        The same 4-tuple reused later by a new socket gets a different creation time, so it is a
        new connection rather than a continuation.
        """
        created = 0 if self.created_at is None else int(self.created_at.timestamp() * 1000)
        remote = f"{self.remote_address or '-'}|{self.remote_port or 0}"
        return (
            f"{self.protocol}|{self.local_address}|{self.local_port}|{remote}|{self.pid}|{created}"
        )

    @property
    def is_listener(self) -> bool:
        return self.direction in (Direction.LISTENING, Direction.BOUND)


class NetworkSnapshot(Frozen):
    """All sockets from one collection pass.

    ``unavailable_tables`` lists tables (e.g. ``"UDP/IPV6"``) that failed; the others are still
    reported, so one broken table never blanks the whole view.
    """

    timestamp: AwareDatetime
    connections: tuple[NetworkConnection, ...]
    unavailable_tables: tuple[str, ...] = ()


class CorrelatedConnection(Frozen):
    """A socket joined to the process instance that owns it (Phase 3)."""

    connection: NetworkConnection
    attribution: Attribution
    process_key: str | None = None
    process_name: str | None = None
    exe: str | None = None

    @property
    def pid(self) -> int:
        return self.connection.pid
