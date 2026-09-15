"""Pure networking helpers: address classification, formatting, and input validation."""

from __future__ import annotations

import ipaddress
from typing import Final

from winsentinel.core.models import AddressScope, NetworkConnection
from winsentinel.errors import InvalidInputError

# Windows' default dynamic (ephemeral) port range since Vista: 49152-65535.
EPHEMERAL_PORT_START: Final = 49152
MAX_PORT: Final = 65535

# "Private" means genuinely internal networks. Python's ``is_private`` also covers documentation,
# benchmarking and other special-purpose ranges, which are classified RESERVED here instead.
_INTERNAL_NETWORKS: Final = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def classify_address(address: str) -> AddressScope:
    """Classify an IP address.

    Ordering matters: loopback/link-local/multicast are checked before internal ranges.
    IPv4-mapped IPv6 addresses (``::ffff:1.2.3.4``) are classified by their IPv4 address.
    PRIVATE = RFC 1918, carrier-grade NAT (RFC 6598) and IPv6 unique-local (RFC 4193).
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return AddressScope.RESERVED
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return AddressScope.UNSPECIFIED
    if ip.is_loopback:
        return AddressScope.LOOPBACK
    if ip.is_link_local:
        return AddressScope.LINK_LOCAL
    if ip.is_multicast:
        return AddressScope.MULTICAST
    if any(ip.version == net.version and ip in net for net in _INTERNAL_NETWORKS):
        return AddressScope.PRIVATE
    if ip.is_global:
        return AddressScope.PUBLIC
    return AddressScope.RESERVED


def format_endpoint(address: str | None, port: int | None) -> str:
    """``1.2.3.4:443``, ``[2001:db8::1]:443``, or ``*`` for no endpoint."""
    if address is None:
        return "*"
    host = f"[{address}]" if ":" in address else address
    return host if port is None else f"{host}:{port}"


def validate_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_PORT:
        raise InvalidInputError(
            f"Invalid port {value!r}: must be an integer between 0 and {MAX_PORT}"
        )
    return value


def validate_ip(value: str) -> str:
    """Validate and canonicalize an IP address (no hostnames, no CIDR)."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise InvalidInputError(f"Invalid IP address {value!r}") from None


def is_external(connection: NetworkConnection) -> bool:
    return connection.remote_scope is AddressScope.PUBLIC
