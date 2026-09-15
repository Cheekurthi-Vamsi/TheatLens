"""Live, btop-style security dashboard (Phase 9).

Draws the running engine's state as a single refreshing screen: a system header, a process
table, active network connections, current alerts, and a recent-event ticker. It renders the
models the engine already maintains — it holds no detection or collection logic of its own.

Performance: one Rich ``Live`` render per refresh (default every second). Data is read from the
in-memory :class:`SystemState`, :class:`AlertManager` and :class:`DetectionEngine` (all
thread-safe), plus a single ``psutil`` call for host CPU/RAM. No polling of its own.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

import psutil
from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from winsentinel import __version__
from winsentinel.core.models import (
    TERMINAL_STATUSES,
    Alert,
    CorrelatedConnection,
    ProcessInfo,
    SecurityEvent,
    Severity,
)
from winsentinel.ui import colors
from winsentinel.ui.event_stream import format_event
from winsentinel.ui.formatting import (
    format_bytes,
    format_percent,
    sanitize_display,
)
from winsentinel.ui.keyreader import KeyReader
from winsentinel.utils.networking import format_endpoint

if TYPE_CHECKING:
    from winsentinel.core.engine import Engine
    from winsentinel.detection.alerting import AlertManager
    from winsentinel.detection.engine import DetectionEngine

TITLE: Final = "THREATLENS"
SUBTITLE: Final = "Windows Security Monitor"
_RECENT_EVENTS: Final = 200
_SEVERITY_RANK: Final = {s: i for i, s in enumerate(reversed(list(Severity)))}


def _meter(fraction: float, width: int, style: str) -> Text:
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)
    bar = Text()
    bar.append("█" * filled, style=style)
    bar.append("─" * (width - filled), style=colors.MUTED)
    return bar


@dataclass(slots=True)
class DashboardOptions:
    process_sort: str = "cpu"  # cpu | memory | name
    paused: bool = False
    show_loopback: bool = False


@dataclass(slots=True)
class _Recents:
    events: list[SecurityEvent] = field(default_factory=list)

    def add(self, event: SecurityEvent) -> None:
        self.events.append(event)
        if len(self.events) > _RECENT_EVENTS:
            del self.events[: len(self.events) - _RECENT_EVENTS]


class Dashboard:
    def __init__(
        self,
        console: Console,
        engine: Engine,
        detection: DetectionEngine,
        alerts: AlertManager,
        *,
        elevated: bool,
        refresh: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._console = console
        self._engine = engine
        self._detection = detection
        self._alerts = alerts
        self._elevated = elevated
        self._refresh = refresh
        self._clock = clock
        self._options = DashboardOptions()
        self._recents = _Recents()
        self._started = clock()

    def on_event(self, event: SecurityEvent) -> None:
        """Bus subscriber (runs on the dispatcher thread): buffer for the ticker."""
        self._recents.add(event)

    # -- run loop ---------------------------------------------------------------------------

    def run(self, *, duration: float | None = None) -> None:
        keys = KeyReader()
        keys.start()
        deadline = None if duration is None else self._clock() + duration
        try:
            with Live(
                self.render(),
                console=self._console,
                screen=self._console.is_terminal,  # alternate screen only on a real terminal
                refresh_per_second=4,
                transient=False,
            ) as live:
                while True:
                    if not self._handle_keys(keys):
                        return
                    live.update(self.render())
                    if deadline is not None and self._clock() >= deadline:
                        return
                    time.sleep(min(self._refresh, 0.25))
        except KeyboardInterrupt:
            return
        finally:
            keys.stop()

    def _handle_keys(self, keys: KeyReader) -> bool:
        while (key := keys.get()) is not None:
            lowered = key.lower()
            if lowered in ("q", "\x1b"):  # q or Esc
                return False
            if lowered == "p":
                self._options.process_sort = "cpu"
            elif lowered == "m":
                self._options.process_sort = "memory"
            elif lowered == "n":
                self._options.process_sort = "name"
            elif lowered == "l":
                self._options.show_loopback = not self._options.show_loopback
            elif key == " ":
                self._options.paused = not self._options.paused
        return True

    # -- rendering --------------------------------------------------------------------------

    def render(self) -> RenderableType:
        processes = self._engine.state.processes()
        connections = self._engine.state.connections()
        alerts = self._alerts.alerts()
        alert_by_key: dict[str, Alert] = {
            a.process_key: a for a in alerts if a.process_key and a.status not in TERMINAL_STATUSES
        }

        layout = Layout()
        layout.split_column(
            Layout(self._header(processes, connections, alerts), name="header", size=6),
            Layout(name="body"),
            Layout(self._footer(), name="footer", size=1),
        )
        layout["body"].split_row(
            Layout(self._process_panel(processes, alert_by_key), name="left", ratio=3),
            Layout(name="right", ratio=2),
        )
        layout["right"].split_column(
            Layout(self._network_panel(connections, alert_by_key), name="net"),
            Layout(self._alert_panel(alerts), name="alerts"),
            Layout(self._events_panel(), name="events"),
        )
        return layout

    def _header(
        self,
        processes: Sequence[ProcessInfo],
        connections: Sequence[CorrelatedConnection],
        alerts: Sequence[Alert],
    ) -> RenderableType:
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        active_alerts = sum(1 for a in alerts if a.status not in TERMINAL_STATUSES)
        critical = sum(
            1
            for a in alerts
            if a.severity is Severity.CRITICAL and a.status not in TERMINAL_STATUSES
        )
        uptime = int(self._clock() - self._started)

        title = Text()
        title.append(f" {TITLE} ", style="bold white on blue")
        title.append(f"  {SUBTITLE}", style="bold")
        title.append(f"   v{__version__}", style=colors.MUTED)
        title.append(
            "   PAUSED" if self._options.paused else "   ● MONITORING",
            style="yellow" if self._options.paused else "green",
        )

        stats = Table.grid(expand=True)
        for _ in range(4):
            stats.add_column(ratio=1)
        alert_style = "bold red" if active_alerts else "green"
        stats.add_row(
            Text.assemble(("Processes  ", colors.MUTED), (str(len(processes)), "bold")),
            Text.assemble(("Connections  ", colors.MUTED), (str(len(connections)), "bold")),
            Text.assemble(
                ("Alerts  ", colors.MUTED),
                (str(active_alerts), alert_style),
                (f"  ({critical} critical)" if critical else "", "red"),
            ),
            Text.assemble(("Uptime  ", colors.MUTED), (_format_uptime(uptime), "bold")),
        )
        meters = Table.grid(expand=True)
        meters.add_column(ratio=1)
        meters.add_column(ratio=1)
        meters.add_row(
            Text.assemble(
                ("CPU ", colors.MUTED),
                _meter(cpu / 100, 22, _load_style(cpu)),
                (f" {cpu:4.0f}%", _load_style(cpu)),
            ),
            Text.assemble(
                ("RAM ", colors.MUTED),
                _meter(memory.percent / 100, 22, _load_style(memory.percent)),
                (f" {memory.percent:4.0f}%", _load_style(memory.percent)),
                (f"  {format_bytes(memory.used)}/{format_bytes(memory.total)}", colors.MUTED),
            ),
        )
        privilege = "administrator" if self._elevated else "standard user"
        return Panel(
            Group(title, Text(""), stats, meters),
            border_style="blue",
            subtitle=Text(f"{privilege} · every {self._refresh:g}s", style=colors.MUTED),
            subtitle_align="right",
        )

    def _process_panel(
        self, processes: Sequence[ProcessInfo], alert_by_key: dict[str, Alert]
    ) -> RenderableType:
        sort = self._options.process_sort
        if sort == "memory":
            ordered = sorted(processes, key=lambda p: -(p.working_set or 0))
        elif sort == "name":
            ordered = sorted(processes, key=lambda p: p.name.lower())
        else:
            ordered = sorted(processes, key=lambda p: (p.pid == 0, -(p.cpu_percent or 0.0)))

        table = Table(box=None, expand=True, pad_edge=False, header_style=colors.HEADER)
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("PROCESS", no_wrap=True, ratio=2)
        table.add_column("USER", no_wrap=True, ratio=2, overflow="ellipsis")
        table.add_column("CPU%", justify="right", no_wrap=True)
        table.add_column("MEM", justify="right", no_wrap=True)
        table.add_column("RISK", no_wrap=True)
        for p in ordered[:40]:
            alert = alert_by_key.get(p.process_key)
            name_style = "bold red" if alert else ("red" if p.suspended else "")
            risk = (
                Text(alert.severity.value, style=colors.SEVERITY_STYLES[alert.severity])
                if alert
                else Text("-", style=colors.MUTED)
            )
            table.add_row(
                str(p.pid),
                Text(sanitize_display(p.name), style=name_style),
                Text(sanitize_display(p.username or "-"), style=colors.MUTED),
                Text(format_percent(p.cpu_percent), style=_load_style(p.cpu_percent or 0)),
                format_bytes(p.working_set),
                risk,
            )
        return Panel(
            table, title=f"PROCESSES  (sort: {sort})", title_align="left", border_style="cyan"
        )

    def _network_panel(
        self, connections: Sequence[CorrelatedConnection], alert_by_key: dict[str, Alert]
    ) -> RenderableType:
        active = [
            c
            for c in connections
            if c.connection.remote_address is not None
            and (
                self._options.show_loopback
                or (
                    c.connection.remote_scope is not None
                    and c.connection.remote_scope.value != "LOOPBACK"
                )
            )
        ]
        active.sort(
            key=lambda c: (
                c.process_key not in alert_by_key,
                c.connection.remote_scope.value != "PUBLIC" if c.connection.remote_scope else True,
            )
        )
        table = Table(box=None, expand=True, pad_edge=False, header_style=colors.HEADER)
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("PROCESS", no_wrap=True, overflow="ellipsis", ratio=2)
        table.add_column("REMOTE", no_wrap=True, ratio=3, overflow="ellipsis")
        table.add_column("STATE", no_wrap=True)
        table.add_column("RISK", no_wrap=True)
        for c in active[:16]:
            conn = c.connection
            alert = alert_by_key.get(c.process_key or "")
            scope = conn.remote_scope
            remote_style = "bold yellow" if scope and scope.value == "PUBLIC" else ""
            risk = (
                Text(alert.severity.value, style=colors.SEVERITY_STYLES[alert.severity])
                if alert
                else Text("LOW", style="green")
            )
            table.add_row(
                str(conn.pid),
                Text(sanitize_display(c.process_name or "-")),
                Text(format_endpoint(conn.remote_address, conn.remote_port), style=remote_style),
                Text(conn.state.value, style=colors.MUTED),
                risk,
            )
        subtitle = f"{len(active)} external/active" if active else "no active external connections"
        return Panel(table, title=f"NETWORK  ({subtitle})", title_align="left", border_style="cyan")

    def _alert_panel(self, alerts: Sequence[Alert]) -> RenderableType:
        active = [a for a in alerts if a.status not in TERMINAL_STATUSES]
        if not active:
            body: RenderableType = Align.center(
                Text("No active alerts", style="green"), vertical="middle"
            )
        else:
            table = Table(box=None, expand=True, pad_edge=False, show_header=False)
            table.add_column(no_wrap=True)
            table.add_column(no_wrap=True)
            table.add_column(no_wrap=True, overflow="ellipsis", ratio=1)
            for a in sorted(active, key=lambda x: (-_SEVERITY_RANK[x.severity], -x.risk_score))[:8]:
                table.add_row(
                    Text(f"{a.severity.value:>8}", style=colors.SEVERITY_STYLES[a.severity]),
                    Text(f"{a.risk_score:>3}", style="bold"),
                    Text(
                        sanitize_display(
                            f"{a.process_name or '?'} — {', '.join(a.rules_triggered)}"
                        )
                    ),
                )
            body = table
        return Panel(
            body,
            title=f"ALERTS  ({len(active)} active)",
            title_align="left",
            border_style="red" if active else "green",
        )

    def _events_panel(self) -> RenderableType:
        events = self._recents.events
        shown = [
            e
            for e in events
            if self._options.show_loopback or e.data.get("remote_scope") != "LOOPBACK"
        ]
        lines = [format_event(e) for e in shown[-8:]]
        body: RenderableType = (
            Group(*lines) if lines else Text("waiting for activity…", style=colors.MUTED)
        )
        return Panel(body, title="RECENT ACTIVITY", title_align="left", border_style=colors.MUTED)

    def _footer(self) -> RenderableType:
        keys = [
            ("Q", "quit"),
            ("P", "cpu"),
            ("M", "mem"),
            ("N", "name"),
            ("L", "loopback"),
            ("Space", "pause"),
        ]
        text = Text()
        for key, label in keys:
            text.append(f" {key} ", style="bold black on cyan")
            text.append(f" {label}  ", style=colors.MUTED)
        return Align.center(text)


def _load_style(percent: float) -> str:
    if percent >= 80:
        return "bold red"
    if percent >= 50:
        return "yellow"
    return "green"


def _format_uptime(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"
