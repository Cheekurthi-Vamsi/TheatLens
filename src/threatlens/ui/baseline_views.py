"""Rendering for baselines and the allowlist."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from threatlens.detection.baseline import BaselineDiff, BaselineItemKind
from threatlens.ui import colors
from threatlens.ui.formatting import sanitize_display
from threatlens.utils.time import format_local

_KIND_HEADINGS: dict[BaselineItemKind, str] = {
    BaselineItemKind.PROCESS: "NEW EXECUTABLES",
    BaselineItemKind.LISTENER: "NEW LISTENERS",
    BaselineItemKind.PERSISTENCE: "NEW PERSISTENCE",
    BaselineItemKind.SERVICE: "NEW SERVICES",
}


def baseline_compare_view(
    baseline_name: str, grouped: Mapping[BaselineItemKind, list[BaselineDiff]], *, expired: bool
) -> RenderableType:
    parts: list[RenderableType] = []
    if expired:
        parts.append(
            Text(
                "⚠ This baseline has expired; re-capture it to trust the comparison.",
                style="yellow",
            )
        )
        parts.append(Text(""))
    if not grouped:
        parts.append(
            Text(
                "No changes since the baseline. Nothing new is running, listening or persisting.",
                style="green",
            )
        )
        return Group(*parts)
    for kind in (
        BaselineItemKind.PROCESS,
        BaselineItemKind.LISTENER,
        BaselineItemKind.PERSISTENCE,
        BaselineItemKind.SERVICE,
    ):
        diffs = grouped.get(kind)
        if not diffs:
            continue
        parts.append(Text(f"{_KIND_HEADINGS[kind]} ({len(diffs)})", style="bold underline"))
        for diff in diffs:
            parts.append(Text(f"  + {sanitize_display(diff.label)}", style="yellow"))
        parts.append(Text(""))
    parts.append(
        Text(
            "These are additions since the baseline — investigate any you did not expect.",
            style=colors.MUTED,
        )
    )
    return Group(*parts)


def baselines_table(rows: Sequence[sqlite3.Row]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("ID", no_wrap=True, style="bold")
    table.add_column("NAME", no_wrap=True, overflow="ellipsis", ratio=1)
    table.add_column("CREATED", no_wrap=True)
    table.add_column("EXPIRES", no_wrap=True)
    table.add_column("ITEMS", justify="right")
    table.add_column("HOST", no_wrap=True)
    for row in rows:
        table.add_row(
            row["baseline_id"][:8],
            Text(sanitize_display(row["name"])),
            _fmt(row["created_at"]),
            _fmt(row["expires_at"]) if row["expires_at"] else "-",
            str(row["item_count"]),
            Text(sanitize_display(row["hostname"]), style=colors.MUTED),
        )
    return table


def allowlist_table(rows: Sequence[sqlite3.Row]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("TYPE", no_wrap=True)
    table.add_column("VALUE", overflow="ellipsis", ratio=1)
    table.add_column("RULES", no_wrap=True)
    table.add_column("REASON", overflow="ellipsis")
    table.add_column("EXPIRES", no_wrap=True)
    for row in rows:
        table.add_row(
            Text(row["match_type"], style="cyan"),
            Text(sanitize_display(row["value"])),
            Text(row["rule_ids"] or "all", style=colors.MUTED),
            Text(sanitize_display(row["reason"] or "-"), style=colors.MUTED),
            _fmt(row["expires_at"]) if row["expires_at"] else "never",
        )
    return table


def _fmt(iso: str) -> str:
    from datetime import datetime

    return format_local(datetime.fromisoformat(iso))
