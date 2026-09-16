"""Rich renderables for sockets and process ↔ network correlation."""

from __future__ import annotations

from collections.abc import Sequence

from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from threatlens.core.models import (
    AddressScope,
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    Direction,
    SignatureStatus,
)
from threatlens.correlation.process_network import ConnectionChain, ProcessConnections
from threatlens.ui import colors
from threatlens.ui.formatting import sanitize_display
from threatlens.utils.networking import format_endpoint
from threatlens.utils.time import format_clock

SCOPE_STYLES: dict[AddressScope, str] = {
    AddressScope.PUBLIC: "bold yellow",
    AddressScope.PRIVATE: "cyan",
    AddressScope.LOOPBACK: colors.MUTED,
    AddressScope.LINK_LOCAL: colors.MUTED,
    AddressScope.UNSPECIFIED: "magenta",
    AddressScope.MULTICAST: colors.MUTED,
    AddressScope.RESERVED: colors.MUTED,
}

STATE_STYLES: dict[ConnectionState, str] = {
    ConnectionState.ESTABLISHED: "green",
    ConnectionState.LISTEN: "magenta",
    ConnectionState.SYN_SENT: "yellow",
    ConnectionState.NONE: colors.MUTED,
}

ATTRIBUTION_NOTES: dict[Attribution, str] = {
    Attribution.KERNEL: "<kernel>",
    Attribution.UNATTRIBUTED: "<unattributed>",
    Attribution.PID_REUSE_SUSPECTED: "<pid reused>",
}


def process_label(item: CorrelatedConnection) -> Text:
    """Process name plus service (owner module) when it differs, e.g. ``svchost.exe (Dnscache)``."""
    note = ATTRIBUTION_NOTES.get(item.attribution)
    if item.process_name is None or item.attribution is Attribution.PID_REUSE_SUSPECTED:
        return Text(note or "<unknown>", style=colors.MUTED)
    text = Text(sanitize_display(item.process_name))
    module = item.connection.owner_module
    if module and module.lower() != item.process_name.lower():
        text.append(f" ({sanitize_display(module)})", style="cyan")
    return text


def _endpoint(address: str | None, port: int | None, scope: AddressScope | None) -> Text:
    return Text(
        format_endpoint(address, port), style=SCOPE_STYLES.get(scope, "") if scope else colors.MUTED
    )


def connections_table(items: Sequence[CorrelatedConnection]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("PROTO", no_wrap=True)
    table.add_column("LOCAL", no_wrap=True, min_width=12)
    table.add_column("REMOTE", no_wrap=True, min_width=12)
    table.add_column("STATE", no_wrap=True)
    table.add_column("DIR", no_wrap=True)
    table.add_column("SCOPE", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True, min_width=5)
    table.add_column("PROCESS", no_wrap=True, overflow="ellipsis", ratio=1, min_width=12)

    for item in items:
        c = item.connection
        protocol = f"{c.protocol.value}{'6' if c.family.value == 'IPV6' else ''}"
        scope = c.remote_scope if c.remote_scope is not None else c.local_scope
        table.add_row(
            Text(protocol),
            _endpoint(c.local_address, c.local_port, c.local_scope),
            _endpoint(c.remote_address, c.remote_port, c.remote_scope),
            Text(c.state.value, style=STATE_STYLES.get(c.state, "")),
            Text(_direction_label(c.direction), style=colors.MUTED),
            Text(scope.value, style=SCOPE_STYLES.get(scope, "")),
            Text(str(c.pid)),
            process_label(item),
        )
    return table


def process_network_table(items: Sequence[CorrelatedConnection]) -> Table:
    """Compact socket table for a single process (used by ``inspect``)."""
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("PROTO", no_wrap=True)
    table.add_column("LOCAL", no_wrap=True)
    table.add_column("REMOTE", no_wrap=True)
    table.add_column("STATE", no_wrap=True)
    table.add_column("DIR", no_wrap=True)
    table.add_column("SCOPE", no_wrap=True)
    table.add_column("OPENED", no_wrap=True)
    table.add_column("SERVICE", no_wrap=True, overflow="ellipsis")
    for item in items:
        c = item.connection
        scope = c.remote_scope if c.remote_scope is not None else c.local_scope
        module = c.owner_module or ""
        service = (
            "" if item.process_name and module.lower() == item.process_name.lower() else module
        )
        table.add_row(
            Text(f"{c.protocol.value}{'6' if c.family.value == 'IPV6' else ''}"),
            _endpoint(c.local_address, c.local_port, c.local_scope),
            _endpoint(c.remote_address, c.remote_port, c.remote_scope),
            Text(c.state.value, style=STATE_STYLES.get(c.state, "")),
            Text(_direction_label(c.direction), style=colors.MUTED),
            Text(scope.value, style=SCOPE_STYLES.get(scope, "")),
            Text(format_clock(c.created_at) if c.created_at else "-", style=colors.MUTED),
            Text(sanitize_display(service), style="cyan"),
        )
    return table


def process_connections_tree(
    groups: Sequence[ProcessConnections], *, title: str, show_signature: bool = False
) -> Tree:
    """``connections`` view: each process with its sockets beneath it."""
    tree = Tree(Text(title, style="bold"), guide_style=colors.MUTED)
    for group in groups:
        header = Text()
        process = group.process
        if process is None:
            header.append(ATTRIBUTION_NOTES.get(group.attribution, "<unknown>"), style=colors.MUTED)
            header.append(f"  PID {group.pid}", style="cyan")
        else:
            header.append(sanitize_display(process.name), style="bold")
            header.append(f"  PID {process.pid}", style="cyan")
            if process.username:
                header.append(f"  {sanitize_display(process.username)}", style=colors.MUTED)
            if show_signature and process.signature is not None:
                status = process.signature.status
                header.append(f"  {status.value}", style=colors.SIGNATURE_STYLES[status])
                if status is SignatureStatus.VALID and process.signature.signer:
                    header.append(
                        f" ({sanitize_display(process.signature.signer)})", style=colors.MUTED
                    )
            if process.exe:
                header.append(f"\n{sanitize_display(process.exe)}", style=colors.MUTED)
        branch = tree.add(header)
        for item in group.connections:
            c = item.connection
            line = Text(f"{c.protocol.value}{'6' if c.family.value == 'IPV6' else ''}  ")
            line.append_text(_endpoint(c.local_address, c.local_port, c.local_scope))
            line.append(
                " → " if c.direction is not Direction.INBOUND else " ← ", style=colors.MUTED
            )
            line.append_text(_endpoint(c.remote_address, c.remote_port, c.remote_scope))
            line.append(f"  {c.state.value}", style=STATE_STYLES.get(c.state, ""))
            if c.remote_scope is not None:
                line.append(f"  {c.remote_scope.value}", style=SCOPE_STYLES.get(c.remote_scope, ""))
            if c.created_at is not None:
                line.append(f"  opened {format_clock(c.created_at)}", style=colors.MUTED)
            module = c.owner_module
            if module and process is not None and module.lower() != process.name.lower():
                line.append(f"  [{sanitize_display(module)}]", style="cyan")
            branch.add(line)
    return tree


def connection_chain_text(chain: ConnectionChain) -> Text:
    """``explorer.exe → powershell.exe → tool.exe ⇒ TCP 203.0.113.5:4444``."""
    text = Text()
    for ancestor in reversed(chain.ancestors):
        text.append(sanitize_display(ancestor.name))
        text.append(f" ({ancestor.pid})", style=colors.MUTED)
        text.append("  →  ", style=colors.MUTED)
    if chain.process is not None:
        text.append(sanitize_display(chain.process.name), style="bold")
        text.append(f" ({chain.process.pid})", style=colors.MUTED)
    else:
        text.append(
            ATTRIBUTION_NOTES.get(chain.connection.attribution, "<unknown>"), style=colors.MUTED
        )
    c = chain.connection.connection
    text.append("  ⇒  ", style="bold")
    text.append(f"{c.protocol.value} ")
    text.append_text(_endpoint(c.remote_address, c.remote_port, c.remote_scope))
    return text


def _direction_label(direction: Direction) -> str:
    return {
        Direction.OUTBOUND: "out",
        Direction.INBOUND: "in",
        Direction.LISTENING: "listen",
        Direction.BOUND: "bound",
        Direction.UNKNOWN: "?",
    }[direction]
