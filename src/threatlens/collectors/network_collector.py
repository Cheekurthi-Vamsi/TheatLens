"""Network collector (Phase 2).

Turns the four IP Helper socket tables (TCP and UDP, IPv4 and IPv6) into :class:`NetworkSnapshot`
objects. Windows API details, permissions and limitations are documented in
:mod:`threatlens.utils.iphlpapi`.

What this module adds on top of the raw tables
    * **Direction inference.** The tables do not record who initiated a TCP connection. A socket
      whose local port matches a listening socket on the same (or wildcard) address is inbound;
      any other connected socket is outbound. This is an *inference* and the model says so.
    * **Scope classification** of local/remote addresses (loopback, private, public, …).
    * **Owner-module caching.** The service-name lookup is done once per socket identity.
    * **Partial failure.** Each table is independent: a failing IPv6 UDP table still leaves the
      other three in the snapshot, and the failure is listed in ``unavailable_tables``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol

from threatlens.core.models import (
    AddressFamily,
    ConnectionState,
    Direction,
    NetworkConnection,
    NetworkSnapshot,
    TransportProtocol,
)
from threatlens.errors import CollectorUnavailableError
from threatlens.utils import iphlpapi
from threatlens.utils.iphlpapi import RawSocketEntry
from threatlens.utils.networking import classify_address
from threatlens.utils.time import filetime_to_datetime, utc_now

logger = logging.getLogger(__name__)

TABLES: Final[tuple[tuple[TransportProtocol, AddressFamily], ...]] = (
    (TransportProtocol.TCP, AddressFamily.IPV4),
    (TransportProtocol.TCP, AddressFamily.IPV6),
    (TransportProtocol.UDP, AddressFamily.IPV4),
    (TransportProtocol.UDP, AddressFamily.IPV6),
)
# Owner lookups are skipped for PID 0 (no owner) and PID 4 (always "System").
_NO_OWNER_LOOKUP_PIDS: Final = frozenset({0, 4})
# Wildcard ("any interface") addresses, used for matching table rows — nothing is bound here.
_WILDCARD: Final[dict[AddressFamily, str]] = {
    AddressFamily.IPV4: "0.0.0.0",  # noqa: S104
    AddressFamily.IPV6: "::",
}


class SocketTableSource(Protocol):
    def query(
        self, protocol: TransportProtocol, family: AddressFamily
    ) -> Sequence[RawSocketEntry]: ...
    def owner_module(self, entry: RawSocketEntry) -> str: ...


class IpHelperSocketSource:
    """Production :class:`SocketTableSource`."""

    def query(self, protocol: TransportProtocol, family: AddressFamily) -> Sequence[RawSocketEntry]:
        return iphlpapi.query_socket_table(protocol.value, family is AddressFamily.IPV6)

    def owner_module(self, entry: RawSocketEntry) -> str:
        return iphlpapi.owner_module_name(entry)


def tcp_state(raw_state: int) -> ConnectionState:
    name = iphlpapi.TCP_STATE_NAMES.get(raw_state)
    return ConnectionState(name) if name else ConnectionState.NONE


def infer_directions(connections: Iterable[NetworkConnection]) -> list[NetworkConnection]:
    """Assign :class:`Direction` to each socket. Pure function over one snapshot.

    Rules:
      * TCP ``LISTEN`` → LISTENING; UDP → BOUND.
      * Connected TCP socket whose local port is listened on at the same address (or a wildcard
        address of the same family) → INBOUND; otherwise → OUTBOUND.
      * TCP socket without a remote endpoint that is not listening → UNKNOWN.
    """
    items = list(connections)
    listening: set[tuple[AddressFamily, str, int]] = {
        (c.family, c.local_address, c.local_port)
        for c in items
        if c.protocol is TransportProtocol.TCP and c.state is ConnectionState.LISTEN
    }

    def direction(c: NetworkConnection) -> Direction:
        if c.protocol is TransportProtocol.UDP:
            return Direction.BOUND
        if c.state is ConnectionState.LISTEN:
            return Direction.LISTENING
        if c.remote_address is None:
            return Direction.UNKNOWN
        for address in (c.local_address, _WILDCARD[c.family]):
            if (c.family, address, c.local_port) in listening:
                return Direction.INBOUND
        return Direction.OUTBOUND

    return [c.model_copy(update={"direction": direction(c)}) for c in items]


@dataclass(frozen=True, slots=True)
class NetworkCollectorOptions:
    resolve_owner_modules: bool = True


class NetworkCollector:
    """Produces :class:`NetworkSnapshot` objects. Not thread-safe; one instance per consumer."""

    name: Final = "network_collector"

    def __init__(
        self,
        source: SocketTableSource | None = None,
        options: NetworkCollectorOptions | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._source = source or IpHelperSocketSource()
        self._options = options or NetworkCollectorOptions()
        self._clock = clock
        # None = lookup failed (e.g. access denied); cached so it is not retried every poll.
        self._owner_cache: dict[tuple[object, ...], str | None] = {}

    def collect(self) -> NetworkSnapshot:
        """Collect all tables. Raises :class:`CollectorUnavailableError` if every table fails."""
        observed_at = self._clock()
        entries: list[tuple[TransportProtocol, AddressFamily, RawSocketEntry]] = []
        failures: list[str] = []
        for protocol, family in TABLES:
            try:
                entries.extend((protocol, family, e) for e in self._source.query(protocol, family))
            except OSError as exc:
                failures.append(f"{protocol.value}/{family.value}")
                logger.warning(
                    "event=SOCKET_TABLE_UNAVAILABLE table=%s/%s error=%s", protocol, family, exc
                )
        if len(failures) == len(TABLES):
            raise CollectorUnavailableError("All socket tables failed: " + ", ".join(failures))

        connections = [
            self._build(protocol, family, entry, observed_at) for protocol, family, entry in entries
        ]
        self._prune({entry.identity for _, _, entry in entries})
        return NetworkSnapshot(
            timestamp=observed_at,
            connections=tuple(infer_directions(connections)),
            unavailable_tables=tuple(failures),
        )

    def _build(
        self,
        protocol: TransportProtocol,
        family: AddressFamily,
        entry: RawSocketEntry,
        observed_at: datetime,
    ) -> NetworkConnection:
        state = (
            tcp_state(entry.state) if protocol is TransportProtocol.TCP else ConnectionState.NONE
        )
        return NetworkConnection(
            protocol=protocol,
            family=family,
            local_address=entry.local_address,
            local_port=entry.local_port,
            remote_address=entry.remote_address,
            remote_port=entry.remote_port,
            state=state,
            pid=entry.pid,
            created_at=filetime_to_datetime(entry.create_filetime),
            owner_module=self._owner_module(entry),
            local_scope=classify_address(entry.local_address),
            remote_scope=None
            if entry.remote_address is None
            else classify_address(entry.remote_address),
            observed_at=observed_at,
        )

    def _owner_module(self, entry: RawSocketEntry) -> str | None:
        if not self._options.resolve_owner_modules or entry.pid in _NO_OWNER_LOOKUP_PIDS:
            return None
        key = entry.identity
        if key in self._owner_cache:
            return self._owner_cache[key]
        try:
            name: str | None = self._source.owner_module(entry) or None
        except OSError as exc:
            logger.debug("event=OWNER_MODULE_UNAVAILABLE pid=%s error=%s", entry.pid, exc)
            name = None
        self._owner_cache[key] = name
        return name

    def _prune(self, live: set[tuple[object, ...]]) -> None:
        for key in self._owner_cache.keys() - live:
            del self._owner_cache[key]
