"""Rendering for ``threatlens status``."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatlens.core.diagnostics import CheckResult
from threatlens.core.models import ComponentStatus, EngineStatus
from threatlens.ui import colors
from threatlens.ui.formatting import format_bytes, format_percent, sanitize_display

COMPONENT_STYLES: dict[ComponentStatus, str] = {
    ComponentStatus.OK: "green",
    ComponentStatus.STARTING: "cyan",
    ComponentStatus.DEGRADED: "yellow",
    ComponentStatus.UNAVAILABLE: "bold red",
    ComponentStatus.TIMED_OUT: "bold red",
    ComponentStatus.STOPPED: colors.MUTED,
    ComponentStatus.DISABLED: colors.MUTED,
}


def _duration(seconds: float) -> str:
    whole = int(seconds)
    return f"{whole // 3600:02d}:{whole % 3600 // 60:02d}:{whole % 60:02d}"


def _grid() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    return grid


def status_view(
    *,
    now: datetime,
    engine: EngineStatus | None,
    engine_live: bool,
    system_rows: Sequence[tuple[str, str]],
    checks: Sequence[CheckResult],
) -> RenderableType:
    parts: list[RenderableType] = []

    overview = _grid()
    if engine is not None and engine_live:
        uptime = _duration((now - engine.started_at).total_seconds())
        age = max(0.0, (now - engine.updated_at).total_seconds())
        overview.add_row(
            "Engine",
            Text(
                f"RUNNING  (PID {engine.pid}, up {uptime}, updated {age:.0f}s ago)", style="green"
            ),
        )
    elif engine is not None:
        overview.add_row(
            "Engine",
            Text(
                f"NOT RUNNING  (last status {engine.state.value} at "
                f"{engine.updated_at.astimezone():%Y-%m-%d %H:%M:%S})",
                style=colors.MUTED,
            ),
        )
    else:
        overview.add_row(
            "Engine", Text("NOT RUNNING  (start it with 'threatlens monitor')", style=colors.MUTED)
        )
    for label, value in system_rows:
        overview.add_row(label, Text(sanitize_display(value)))
    parts.append(overview)

    if engine is not None and engine_live:
        components = Table(header_style=colors.HEADER, box=None, pad_edge=False)
        components.add_column("COMPONENT", no_wrap=True)
        components.add_column("STATUS", no_wrap=True)
        components.add_column("RUNS", justify="right")
        components.add_column("LAST RUN", justify="right")
        components.add_column("DETAIL", overflow="fold")
        for component in engine.components:
            detail = component.last_error or component.detail or ""
            components.add_row(
                component.name,
                Text(component.status.value, style=COMPONENT_STYLES[component.status]),
                str(component.runs),
                "-"
                if component.last_duration_ms is None
                else f"{component.last_duration_ms:.1f} ms",
                Text(sanitize_display(detail), style=colors.MUTED),
            )
        parts += [Text(""), Text("COMPONENTS", style="bold underline"), components]

        bus, stats = engine.bus, engine.stats
        load = _grid()
        load.add_row(
            "Queue",
            f"{bus.queued} / {bus.capacity}  ·  dropped {bus.dropped}  ·  "
            f"handler errors {bus.handler_errors}",
        )
        rate = "-" if stats.events_per_second is None else f"{stats.events_per_second:.1f}"
        latency = "-" if bus.avg_latency_ms is None else f"{bus.avg_latency_ms:.2f} ms"
        load.add_row("Events", f"{bus.dispatched} dispatched  ·  {rate}/s  ·  latency {latency}")
        load.add_row(
            "State",
            f"{stats.processes} processes ({stats.exited_retained} recently exited)  ·  "
            f"{stats.connections} sockets  ·  {stats.enriched} enriched",
        )
        load.add_row("Detections", f"{stats.detections} from {engine.rules_enabled} rules")
        load.add_row(
            "Engine load",
            f"CPU {format_percent(engine.engine_cpu_percent)} %  ·  "
            f"memory {format_bytes(engine.engine_working_set)}",
        )
        parts += [Text(""), Text("ENGINE", style="bold underline"), load]

    if checks:
        table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
        table.add_column("SELF-TEST", no_wrap=True)
        table.add_column("RESULT", no_wrap=True)
        table.add_column("TIME", justify="right")
        table.add_column("DETAIL", overflow="fold")
        for check in checks:
            table.add_row(
                check.name,
                Text("OK", style="green") if check.ok else Text("FAILED", style="bold red"),
                f"{check.duration_ms:.0f} ms",
                Text(sanitize_display(check.detail), style=colors.MUTED),
            )
        parts += [Text(""), table]

    return Panel(Group(*parts), title="THREATLENS STATUS", title_align="left", border_style="cyan")
