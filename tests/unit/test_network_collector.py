from __future__ import annotations

import ctypes
import socket
import struct

import pytest

from fixtures.fakes import FakeClock, FakeSocketSource, socket_entry
from threatlens.collectors.network_collector import NetworkCollector, infer_directions
from threatlens.core.models import AddressScope, ConnectionState, Direction, TransportProtocol
from threatlens.errors import CollectorUnavailableError, InvalidInputError
from threatlens.utils import iphlpapi
from threatlens.utils.networking import (
    classify_address,
    format_endpoint,
    validate_ip,
    validate_port,
)


def collect(source: FakeSocketSource) -> list:  # type: ignore[type-arg]
    return list(NetworkCollector(source, clock=FakeClock().now).collect().connections)


class TestDirectionAndScope:
    def test_listener_inbound_outbound_and_udp(self) -> None:
        source = FakeSocketSource(
            [
                socket_entry(10, "0.0.0.0", 8080, state="LISTEN"),
                socket_entry(10, "10.0.0.5", 8080, "10.0.0.9", 51000),  # accepted -> inbound
                socket_entry(20, "10.0.0.5", 51001, "93.184.216.7", 443),  # outbound
                socket_entry(30, "127.0.0.1", 5353, protocol="UDP"),
            ]
        )
        observed = sorted(
            (c.pid, c.local_port, c.remote_port or 0, c.direction.value) for c in collect(source)
        )
        assert observed == [
            (10, 8080, 0, "LISTENING"),
            (10, 8080, 51000, "INBOUND"),
            (20, 51001, 443, "OUTBOUND"),
            (30, 5353, 0, "BOUND"),
        ]

    def test_listener_on_specific_address_only_matches_that_address(self) -> None:
        conns = collect(
            FakeSocketSource(
                [
                    socket_entry(10, "127.0.0.1", 9000, state="LISTEN"),
                    socket_entry(20, "10.0.0.5", 9000, "93.184.216.1", 443),  # same port, other IP
                ]
            )
        )
        assert next(c for c in conns if c.pid == 20).direction is Direction.OUTBOUND

    def test_ipv6_wildcard_listener(self) -> None:
        conns = collect(
            FakeSocketSource(
                [
                    socket_entry(10, "::", 443, state="LISTEN"),
                    socket_entry(10, "2001:db8::5", 443, "2001:db8::9", 60000),
                ]
            )
        )
        assert next(c for c in conns if c.remote_address).direction is Direction.INBOUND

    def test_scopes_and_listen_has_no_remote(self) -> None:
        conns = collect(FakeSocketSource([socket_entry(10, "0.0.0.0", 445, state="LISTEN")]))
        (listener,) = conns
        assert listener.remote_address is None and listener.remote_scope is None
        assert listener.local_scope is AddressScope.UNSPECIFIED
        assert listener.state is ConnectionState.LISTEN

    def test_infer_directions_unknown_without_remote(self) -> None:
        from fixtures.fakes import connection

        closed = connection(1, remote=None, remote_port=None, state=ConnectionState.CLOSED)
        (result,) = infer_directions([closed])
        assert result.direction is Direction.UNKNOWN


class TestResilience:
    def test_partial_table_failure_keeps_other_tables(self) -> None:
        source = FakeSocketSource(
            [socket_entry(1), socket_entry(2, protocol="UDP", local_port=53)],
            failing_tables={("UDP", "IPV4"), ("UDP", "IPV6")},
        )
        snapshot = NetworkCollector(source).collect()
        assert [c.protocol for c in snapshot.connections] == [TransportProtocol.TCP]
        assert snapshot.unavailable_tables == ("UDP/IPV4", "UDP/IPV6")

    def test_all_tables_failing_raises(self) -> None:
        tables = {("TCP", "IPV4"), ("TCP", "IPV6"), ("UDP", "IPV4"), ("UDP", "IPV6")}
        with pytest.raises(CollectorUnavailableError):
            NetworkCollector(FakeSocketSource([], failing_tables=tables)).collect()

    def test_owner_module_cached_including_failures(self) -> None:
        source = FakeSocketSource(
            [socket_entry(10), socket_entry(20, local_port=50001)],
            owners={10: "Dnscache", 20: OSError(5, "Access is denied")},
        )
        collector = NetworkCollector(source)
        first = {c.pid: c.owner_module for c in collector.collect().connections}
        collector.collect()
        assert first == {10: "Dnscache", 20: None}
        assert source.owner_calls == 2  # one per socket, not per poll

    def test_owner_lookup_skipped_for_idle_and_system(self) -> None:
        source = FakeSocketSource(
            [socket_entry(0, state="TIME_WAIT"), socket_entry(4, local_port=445)]
        )
        NetworkCollector(source).collect()
        assert source.owner_calls == 0


class TestRawTableDecoding:
    """Build real MIB_TCPTABLE_OWNER_MODULE bytes and decode them — no Windows calls."""

    def _tcp_buffer(self, rows: list[iphlpapi.TcpRowOwnerModule]) -> ctypes.Array[ctypes.c_char]:
        table_type = iphlpapi._table_type(iphlpapi.TcpRowOwnerModule)
        offset = table_type.table.offset  # type: ignore[attr-defined]
        size = offset + len(rows) * ctypes.sizeof(iphlpapi.TcpRowOwnerModule)
        buffer = ctypes.create_string_buffer(size)
        ctypes.c_uint32.from_buffer(buffer).value = len(rows)
        for index, row in enumerate(rows):
            ctypes.memmove(
                ctypes.addressof(buffer) + offset + index * ctypes.sizeof(row),
                ctypes.addressof(row),
                ctypes.sizeof(row),
            )
        return buffer

    @staticmethod
    def _dword_ip(address: str) -> int:
        return int(struct.unpack("<I", socket.inet_aton(address))[0])

    @staticmethod
    def _net_port(port: int) -> int:
        return int(struct.unpack("<H", struct.pack(">H", port))[0])

    def test_decodes_addresses_ports_state_and_timestamp(self) -> None:
        row = iphlpapi.TcpRowOwnerModule(
            dwState=5,
            dwLocalAddr=self._dword_ip("192.168.1.10"),
            dwLocalPort=self._net_port(52122),
            dwRemoteAddr=self._dword_ip("142.250.1.2"),
            dwRemotePort=self._net_port(443),
            dwOwningPid=4212,
            liCreateTimestamp=133_000_000_000_000_000,
        )
        listen = iphlpapi.TcpRowOwnerModule(
            dwState=2, dwLocalAddr=0, dwLocalPort=self._net_port(135), dwOwningPid=1000
        )
        buffer = self._tcp_buffer([row, listen])
        decoded, listener = iphlpapi.parse_table(buffer, len(buffer), "TCP", False)
        assert (decoded.local_address, decoded.local_port) == ("192.168.1.10", 52122)
        assert (decoded.remote_address, decoded.remote_port) == ("142.250.1.2", 443)
        assert (decoded.pid, decoded.state, decoded.create_filetime) == (
            4212,
            5,
            133_000_000_000_000_000,
        )
        assert listener.remote_address is None and listener.local_port == 135

    def test_row_count_larger_than_buffer_is_rejected(self) -> None:
        buffer = self._tcp_buffer([iphlpapi.TcpRowOwnerModule()])
        ctypes.c_uint32.from_buffer(buffer).value = 1000
        with pytest.raises(OSError):
            iphlpapi.parse_table(buffer, len(buffer), "TCP", False)

    def test_structure_sizes(self) -> None:
        assert ctypes.sizeof(iphlpapi.TcpRowOwnerModule) == 160
        assert ctypes.sizeof(iphlpapi.Tcp6RowOwnerModule) == 192
        assert ctypes.sizeof(iphlpapi.UdpRowOwnerModule) == 160
        assert ctypes.sizeof(iphlpapi.Udp6RowOwnerModule) == 176


@pytest.mark.parametrize(
    ("address", "scope"),
    [
        ("0.0.0.0", AddressScope.UNSPECIFIED),
        ("::", AddressScope.UNSPECIFIED),
        ("127.0.0.1", AddressScope.LOOPBACK),
        ("::1", AddressScope.LOOPBACK),
        ("169.254.10.1", AddressScope.LINK_LOCAL),
        ("fe80::1%12", AddressScope.LINK_LOCAL),
        ("10.1.2.3", AddressScope.PRIVATE),
        ("172.16.0.1", AddressScope.PRIVATE),
        ("192.168.0.1", AddressScope.PRIVATE),
        ("100.64.0.1", AddressScope.PRIVATE),  # carrier-grade NAT
        ("fd00::1", AddressScope.PRIVATE),
        ("224.0.0.251", AddressScope.MULTICAST),
        ("8.8.8.8", AddressScope.PUBLIC),
        ("2606:4700::1111", AddressScope.PUBLIC),
        ("::ffff:8.8.8.8", AddressScope.PUBLIC),  # IPv4-mapped
        ("::ffff:192.168.1.1", AddressScope.PRIVATE),
        ("203.0.113.10", AddressScope.RESERVED),  # documentation range: not internal, not global
        ("198.18.0.1", AddressScope.RESERVED),  # benchmarking range
        ("255.255.255.255", AddressScope.RESERVED),
        ("not-an-ip", AddressScope.RESERVED),
    ],
)
def test_classify_address(address: str, scope: AddressScope) -> None:
    assert classify_address(address) is scope


def test_format_endpoint() -> None:
    assert format_endpoint("1.2.3.4", 443) == "1.2.3.4:443"
    assert format_endpoint("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert format_endpoint(None, None) == "*"


def test_validators() -> None:
    assert validate_port(443) == 443
    assert validate_ip(" 2001:DB8::1 ") == "2001:db8::1"
    for bad_port in (-1, 65536, True, "80"):
        with pytest.raises(InvalidInputError):
            validate_port(bad_port)
    for bad_ip in ("999.1.1.1", "example.com", "10.0.0.0/8", "1.2.3.4; rm"):
        with pytest.raises(InvalidInputError):
            validate_ip(bad_ip)
