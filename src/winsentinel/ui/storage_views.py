"""Rendering for stored data: events, log tail, database info."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from winsentinel.core.models.persistence import PersistenceItem
from winsentinel.storage.database import loads
from winsentinel.storage.repositories import DatabaseInfo
from winsentinel.ui import colors
from winsentinel.ui.formatting import format_bytes, sanitize_display
from winsentinel.utils.time import format_local

_EVENT_STYLES = {
    "PROCESS_STARTED": "green",
    "PROCESS_STOPPED": colors.MUTED,
    "PROCESS_ENRICHED": "cyan",
    "CONNECTION_OPENED": "blue",
    "LISTENER_OPENED": "magenta",
    "COLLECTOR_STATUS": "bold yellow",
    "PERSISTENCE_ADDED": "bold magenta",
}


def _event_summary(event_type: str, data: dict[str, Any]) -> str:
    name = data.get("name") or data.get("process") or ""
    if event_type.startswith(("CONNECTION_", "LISTENER_")):
        remote = data.get("remote_address")
        endpoint = (
            f" → {remote}:{data.get('remote_port')}" if remote else f" :{data.get('local_port')}"
        )
        return f"{name} {data.get('protocol', '')}{endpoint}".strip()
    if event_type == "COLLECTOR_STATUS":
        return f"{data.get('component')}: {data.get('status')}"
    if event_type == "PROCESS_ENRICHED":
        return f"{name} {data.get('signature_status', '')}"
    return f"{name} {data.get('exe', '') or ''}".strip()


def events_table(rows: Sequence[sqlite3.Row]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("TIME", no_wrap=True, style=colors.MUTED)
    table.add_column("EVENT", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True, style=colors.MUTED)
    table.add_column("DETAIL", overflow="ellipsis", ratio=1)
    for row in rows:
        data = loads(row["data"]) or {}
        table.add_row(
            format_local(datetime.fromisoformat(row["timestamp"])),
            Text(row["event_type"], style=_EVENT_STYLES.get(row["event_type"], "")),
            "-" if row["pid"] is None else str(row["pid"]),
            Text(sanitize_display(_event_summary(row["event_type"], data))),
        )
    return table


def event_row_json(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "event_type": row["event_type"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "observation": row["observation"],
        "process_key": row["process_key"],
        "pid": row["pid"],
        "data": loads(row["data"]),
    }


def persistence_table(items: Sequence[PersistenceItem]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("KIND", no_wrap=True)
    table.add_column("NAME", no_wrap=True, overflow="ellipsis", max_width=34)
    table.add_column("EXECUTABLE", overflow="ellipsis", ratio=1)
    table.add_column("LOCATION", no_wrap=True, overflow="ellipsis", max_width=30)
    for item in items:
        table.add_row(
            Text(item.kind.value, style="magenta"),
            Text(sanitize_display(item.name)),
            Text(sanitize_display(item.executable or item.command or "-"), style=colors.MUTED),
            Text(sanitize_display(item.location), style=colors.MUTED),
        )
    return table


def db_info_view(info: DatabaseInfo) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column()
    grid.add_row("Path", Text(info.path))
    grid.add_row("Schema version", Text(str(info.version)))
    grid.add_row("Size", Text(format_bytes(info.size_bytes)))
    grid.add_row("", Text(""))
    for table, count in info.counts.items():
        grid.add_row(table, Text(f"{count:,}"))
    return Panel(Group(grid), title="DATABASE", title_align="left", border_style="cyan")
