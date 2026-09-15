"""Rendering for alerts (Phase 6)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from winsentinel.core.models import AlertStatus, Confidence, ScoreContribution, Severity
from winsentinel.ui import colors
from winsentinel.ui.detection_views import CONFIDENCE_STYLES
from winsentinel.ui.formatting import sanitize_display
from winsentinel.utils.time import format_local


class AlertLike(Protocol):
    """The alert surface the views need — satisfied by both the live ``Alert`` and a stored row.

    Members are read-only ``property`` declarations so a frozen model (whose attributes are
    read-only) structurally conforms.
    """

    @property
    def alert_id(self) -> str: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def risk_score(self) -> int: ...
    @property
    def confidence(self) -> Confidence: ...
    @property
    def status(self) -> AlertStatus: ...
    @property
    def pid(self) -> int | None: ...
    @property
    def process_name(self) -> str | None: ...
    @property
    def exe(self) -> str | None: ...
    @property
    def created_at(self) -> datetime: ...
    @property
    def updated_at(self) -> datetime: ...
    @property
    def rules_triggered(self) -> tuple[str, ...]: ...
    @property
    def score_breakdown(self) -> tuple[ScoreContribution, ...]: ...
    @property
    def recommended_actions(self) -> tuple[str, ...]: ...


STATUS_STYLES: dict[AlertStatus, str] = {
    AlertStatus.NEW: "bold red",
    AlertStatus.ACKNOWLEDGED: "yellow",
    AlertStatus.INVESTIGATING: "cyan",
    AlertStatus.RESOLVED: "green",
    AlertStatus.IGNORED: colors.MUTED,
}


def _severity(alert: AlertLike) -> Text:
    return Text(alert.severity.value, style=colors.SEVERITY_STYLES[alert.severity])


def alert_row_id(alert: AlertLike) -> str:
    """Short, stable, human-typeable id (first 8 chars of the UUID)."""
    return alert.alert_id[:8]


def alerts_table(alerts: Sequence[AlertLike]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("ALERT", no_wrap=True, style="bold")
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("RISK", justify="right", no_wrap=True)
    table.add_column("CONF", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("PROCESS", no_wrap=True, overflow="ellipsis", max_width=28)
    table.add_column("RULES", no_wrap=True, overflow="ellipsis", ratio=1)
    table.add_column("STATUS", no_wrap=True)
    table.add_column("UPDATED", no_wrap=True)
    for alert in alerts:
        table.add_row(
            alert_row_id(alert),
            _severity(alert),
            str(alert.risk_score),
            Text(alert.confidence.value, style=CONFIDENCE_STYLES[alert.confidence]),
            "-" if alert.pid is None else str(alert.pid),
            Text(sanitize_display(alert.process_name or "-")),
            Text(", ".join(alert.rules_triggered), style=colors.MUTED),
            Text(alert.status.value, style=STATUS_STYLES[alert.status]),
            Text(format_local(alert.updated_at), style=colors.MUTED),
        )
    return table


def breakdown_text(contributions: Sequence[ScoreContribution]) -> Text:
    text = Text()
    for index, contribution in enumerate(contributions):
        if index:
            text.append("\n")
        text.append(f"  +{contribution.effective:g}  ", style="bold")
        text.append(f"{contribution.rule_id} ", style="bold")
        text.append(sanitize_display(contribution.rule_name))
        text.append(
            f"  (raw {contribution.raw_score}, {contribution.confidence.value.lower()}, "
            f"{contribution.category.lower()})",
            style=colors.MUTED,
        )
    return text


def alert_detail(alert: AlertLike) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("Alert", Text(f"{alert.alert_id}", style="bold"))
    grid.add_row("Severity", _severity(alert))
    grid.add_row(
        "Risk score", Text(f"{alert.risk_score} / 100  ({alert.confidence.value} confidence)")
    )
    grid.add_row("Status", Text(alert.status.value, style=STATUS_STYLES[alert.status]))
    grid.add_row(
        "Process", Text(sanitize_display(f"{alert.process_name or '?'}  (PID {alert.pid})"))
    )
    if alert.exe:
        grid.add_row("Path", Text(sanitize_display(alert.exe)))
    grid.add_row("First seen", Text(format_local(alert.created_at)))
    grid.add_row("Last updated", Text(format_local(alert.updated_at)))

    sections: list[RenderableType] = [
        grid,
        Text(""),
        Text("SCORE BREAKDOWN", style="bold underline"),
        breakdown_text(alert.score_breakdown),
        Text(""),
        Text(
            "This is a combined signal that requires investigation, not a verdict.",
            style=colors.MUTED,
        ),
        Text(""),
        Text("RECOMMENDED ACTIONS", style="bold underline"),
    ]
    sections.extend(Text(f"  • {a}", style="green") for a in alert.recommended_actions)
    return Panel(
        Group(*sections),
        title="SECURITY ALERT",
        title_align="left",
        border_style=colors.SEVERITY_STYLES[alert.severity],
    )


def alert_stream_text(alert: AlertLike) -> Text:
    from winsentinel.utils.time import format_clock

    text = Text(format_clock(alert.updated_at), style=colors.MUTED)
    text.append("  ")
    text.append("⚠ ALERT".ljust(20), style="bold red")
    text.append(_severity(alert))
    text.append(f"  risk {alert.risk_score}", style="bold")
    text.append(f"  [{alert_row_id(alert)}]  ", style=colors.MUTED)
    text.append(sanitize_display(alert.process_name or "?"))
    text.append(f" (PID {alert.pid})", style=colors.MUTED)
    text.append(f"  {', '.join(alert.rules_triggered)}", style=colors.MUTED)
    return text
