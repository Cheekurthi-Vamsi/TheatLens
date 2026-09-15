"""Rendering for response actions: the pre-action warning and the outcome."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from winsentinel.core.models import (
    ActionOutcome,
    CorrelatedConnection,
    ProcessInfo,
    ResponseAction,
    Severity,
)
from winsentinel.response.protection import ProtectionVerdict
from winsentinel.ui import colors
from winsentinel.ui.formatting import format_percent, sanitize_display
from winsentinel.utils.networking import format_endpoint
from winsentinel.utils.time import format_local

_OUTCOME_STYLES = {
    ActionOutcome.SUCCEEDED: "green",
    ActionOutcome.FAILED: "bold red",
    ActionOutcome.CANCELLED: colors.MUTED,
    ActionOutcome.DENIED_BY_POLICY: "bold red",
}
_ACTION_VERB = {
    "SUSPEND_PROCESS": "SUSPEND",
    "TERMINATE_PROCESS": "TERMINATE",
    "RESUME_PROCESS": "RESUME",
}


def action_warning(
    verb: str,
    process: ProcessInfo,
    connections: Sequence[CorrelatedConnection],
    verdict: ProtectionVerdict,
    *,
    risk_score: int | None = None,
    severity: Severity | None = None,
) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("PID", Text(str(process.pid)))
    grid.add_row("Process", Text(sanitize_display(process.name)))
    grid.add_row("Path", Text(sanitize_display(process.exe or "<unknown>")))
    grid.add_row("User", Text(sanitize_display(process.username or "-")))
    grid.add_row("Created", Text(format_local(process.create_time)))
    grid.add_row("CPU", Text(f"{format_percent(process.cpu_percent)} %"))
    external = [
        c
        for c in connections
        if c.connection.remote_scope and c.connection.remote_scope.value == "PUBLIC"
    ]
    if external:
        endpoints = Text()
        for index, c in enumerate(external[:5]):
            if index:
                endpoints.append("\n")
            endpoints.append(
                format_endpoint(c.connection.remote_address, c.connection.remote_port),
                style="yellow",
            )
        grid.add_row("Network", endpoints)
    if risk_score is not None and severity is not None:
        grid.add_row(
            "Risk",
            Text(f"{risk_score}/100 {severity.value}", style=colors.SEVERITY_STYLES[severity]),
        )

    sections: list[RenderableType] = [
        Text(f"You are about to {verb} this process.", style="bold"),
        Text(""),
        grid,
    ]
    if verdict.protected:
        sections += [
            Text(""),
            Text(f"⚠ PROTECTED PROCESS: {verdict.reason}.", style="bold white on red"),
            Text(
                f"{verb.capitalize()}ing it may crash Windows or log you out. Requires "
                "--force-protected to proceed.",
                style="red",
            ),
        ]
    border = "red" if verb.lower() in ("terminate", "suspend") or verdict.protected else "yellow"
    return Panel(
        Group(*sections), title=f"CONFIRM {verb.upper()}", title_align="left", border_style=border
    )


def action_result_text(action: ResponseAction) -> Text:
    verb = _ACTION_VERB.get(action.action_type.value, action.action_type.value)
    text = Text()
    text.append(f"{action.outcome.value}: ", style=_OUTCOME_STYLES[action.outcome])
    text.append(f"{verb} {sanitize_display(action.target)}")
    if action.error:
        text.append(f"\n  {sanitize_display(action.error)}", style=colors.MUTED)
    return text


def actions_table(rows: Sequence[object]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("TIME", no_wrap=True, style=colors.MUTED)
    table.add_column("ACTION", no_wrap=True)
    table.add_column("TARGET", no_wrap=True, overflow="ellipsis", ratio=1)
    table.add_column("OUTCOME", no_wrap=True)
    table.add_column("BY", no_wrap=True, style=colors.MUTED)
    for row in rows:
        outcome = ActionOutcome(row["outcome"])  # type: ignore[index]
        table.add_row(
            format_local_str(row["timestamp"]),  # type: ignore[index]
            Text(row["action_type"]),  # type: ignore[index]
            Text(sanitize_display(row["target"])),  # type: ignore[index]
            Text(outcome.value, style=_OUTCOME_STYLES[outcome]),
            Text(sanitize_display(row["requested_by"])),  # type: ignore[index]
        )
    return table


def format_local_str(iso: str) -> str:
    from datetime import datetime

    return format_local(datetime.fromisoformat(iso))
