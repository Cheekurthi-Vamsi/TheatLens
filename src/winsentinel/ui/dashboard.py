"""Live, btop-style security dashboard.

Draws the running engine's state as a single refreshing screen: a system header, a process
table, active network connections, current alerts, and a recent-event ticker. It renders the
models the engine already maintains — it holds no detection or collection logic of its own.

Interaction:
    * ↑/↓, PgUp/PgDn, Home/End select a process. The selection follows the *process* (by
      ``process_key``), not the row, so re-sorting by CPU never moves it onto another program.
    * ``T`` / Delete asks to stop the selected process. The confirmation panel names the exact
      process; the stop goes through :class:`ResponseManager`, so the protected-process policy,
      the PID-reuse guard and the audit log all apply. Protected processes are refused outright.
    * ``C`` asks to clear RAM (trim working sets). It runs on a background thread so the screen
      stays responsive, and the result is shown in the status line.

Performance: keys are polled every 50 ms and redraw immediately; data and the CPU/RAM sample
refresh at most once per second. Data is read from the engine's thread-safe in-memory state.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

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
    ActionOutcome,
    ActionType,
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
    from winsentinel.response.protection import ProtectionVerdict
    from winsentinel.response.response_manager import ResponseManager

TITLE: Final = "THREATLENS"
SUBTITLE: Final = "Windows Security Monitor"
HEADER_ROWS: Final = 6
FOOTER_ROWS: Final = 2
STOP_REASON: Final = "Stopped from the ThreatLens dashboard"
TRIM_REASON: Final = "Clear RAM requested from the ThreatLens dashboard"
_RECENT_EVENTS: Final = 200
_INPUT_POLL_SECONDS: Final = 0.05
_STATUS_SECONDS: Final = 8.0
_SELECTED_STYLE: Final = "bold black on cyan"
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


@dataclass(frozen=True, slots=True)
class _Data:
    processes: tuple[ProcessInfo, ...]
    connections: tuple[CorrelatedConnection, ...]
    alerts: tuple[Alert, ...]


class ModalKind(StrEnum):
    STOP = "STOP"
    TRIM = "TRIM"


@dataclass(frozen=True, slots=True)
class _Modal:
    kind: ModalKind
    process: ProcessInfo | None = None
    verdict: ProtectionVerdict | None = None


@dataclass(frozen=True, slots=True)
class _Status:
    text: Text
    expires_at: float | None  # None: stays until replaced (e.g. while RAM is being cleared)


def order_processes(processes: Sequence[ProcessInfo], sort: str) -> list[ProcessInfo]:
    if sort == "memory":
        return sorted(processes, key=lambda p: (-(p.working_set or 0), p.pid))
    if sort == "name":
        return sorted(processes, key=lambda p: (p.name.lower(), p.pid))
    # The Idle process's "CPU" is unused capacity; keep it off the top.
    return sorted(processes, key=lambda p: (p.pid == 0, -(p.cpu_percent or 0.0), p.pid))


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
        responses: ResponseManager | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._console = console
        self._engine = engine
        self._detection = detection
        self._alerts = alerts
        self._elevated = elevated
        self._refresh = refresh
        self._responses = responses
        self._clock = clock
        self._options = DashboardOptions()
        self._recents = _Recents()
        self._started = clock()

        self._frozen: _Data | None = None
        self._cpu: float | None = None
        self._memory: Any = None  # psutil svmem
        self._selected_key: str | None = None
        self._selected_index = 0
        self._scroll = 0
        self._modal: _Modal | None = None
        self._status: _Status | None = None
        self._lock = threading.Lock()
        self._trim_thread: threading.Thread | None = None
        self._dirty = True

    def on_event(self, event: SecurityEvent) -> None:
        """Bus subscriber (runs on the dispatcher thread): buffer for the ticker."""
        self._recents.add(event)

    # -- run loop ---------------------------------------------------------------------------

    def run(self, *, duration: float | None = None) -> None:
        keys = KeyReader()
        keys.start()
        deadline = None if duration is None else self._clock() + duration
        draw_interval = min(self._refresh, 1.0)
        next_draw = 0.0
        try:
            with Live(
                self.render(),
                console=self._console,
                screen=self._console.is_terminal,  # alternate screen only on a real terminal
                auto_refresh=False,
                transient=False,
            ) as live:
                while True:
                    if not self._handle_keys(keys):
                        return
                    now = self._clock()
                    if now >= next_draw:
                        self._sample_system()
                        next_draw = now + draw_interval
                        self._dirty = True
                    if self._dirty:
                        self._dirty = False
                        live.update(self.render(), refresh=True)
                    if deadline is not None and now >= deadline:
                        return
                    time.sleep(_INPUT_POLL_SECONDS)
        except KeyboardInterrupt:
            return
        finally:
            keys.stop()

    def wait_for_background_work(self, timeout: float = 30.0) -> None:
        """Join a running RAM trim (used on shutdown and by tests)."""
        thread = self._trim_thread
        if thread is not None:
            thread.join(timeout)

    # -- keys -------------------------------------------------------------------------------

    def _handle_keys(self, keys: KeyReader) -> bool:
        while (key := keys.get()) is not None:
            self._dirty = True
            if self._modal is not None:
                self._handle_modal_key(key)
                continue
            if key in ("UP", "DOWN", "PGUP", "PGDN", "HOME", "END", "DELETE", "ENTER"):
                self._handle_named_key(key)
                continue
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
            elif lowered == "t":
                self._open_stop()
            elif lowered == "c":
                self._open_trim()
            elif key == " ":
                self._toggle_pause()
        return True

    def _handle_named_key(self, key: str) -> None:
        page = self._visible_rows()
        if key == "UP":
            self._move(-1)
        elif key == "DOWN":
            self._move(1)
        elif key == "PGUP":
            self._move(-page)
        elif key == "PGDN":
            self._move(page)
        elif key == "HOME":
            self._move_to(0)
        elif key == "END":
            self._move_to(-1)
        elif key == "DELETE":
            self._open_stop()

    def _handle_modal_key(self, key: str) -> None:
        modal = self._modal
        if modal is None:
            return
        lowered = key.lower()
        if modal.verdict is not None and modal.verdict.protected:
            if key in ("\x1b", "ENTER") or lowered in ("n", "q", "y"):
                self._modal = None  # refusal notice: nothing to confirm
            return
        if lowered == "y":
            self._modal = None
            if modal.kind is ModalKind.STOP and modal.process is not None:
                self._stop(modal.process)
            elif modal.kind is ModalKind.TRIM:
                self._start_trim()
        elif lowered in ("n", "q") or key == "\x1b":
            self._modal = None
            if self._responses is not None:
                action_type = (
                    ActionType.TERMINATE_PROCESS
                    if modal.kind is ModalKind.STOP
                    else ActionType.TRIM_WORKING_SETS
                )
                reason = STOP_REASON if modal.kind is ModalKind.STOP else TRIM_REASON
                self._responses.record_cancelled(action_type, reason=reason, process=modal.process)
            self._flash("Cancelled.", colors.MUTED)

    # -- selection --------------------------------------------------------------------------

    def _live_data(self) -> _Data:
        return _Data(
            processes=tuple(self._engine.state.processes()),
            connections=tuple(self._engine.state.connections()),
            alerts=tuple(self._alerts.alerts()),
        )

    def _data(self) -> _Data:
        if self._options.paused and self._frozen is not None:
            return self._frozen
        return self._live_data()

    def _toggle_pause(self) -> None:
        self._options.paused = not self._options.paused
        self._frozen = self._live_data() if self._options.paused else None

    def _ordered(self) -> list[ProcessInfo]:
        return order_processes(self._data().processes, self._options.process_sort)

    def _visible_rows(self) -> int:
        # Process panel height = screen - header - footer; minus 2 border rows and 1 header row.
        return max(1, self._console.size.height - HEADER_ROWS - FOOTER_ROWS - 3)

    def _position(self, ordered: Sequence[ProcessInfo]) -> int:
        """Row index of the selected process; if it exited, keep the same row. -1 if none."""
        if self._selected_key is None or not ordered:
            return -1
        for index, process in enumerate(ordered):
            if process.process_key == self._selected_key:
                self._selected_index = index
                return index
        index = min(self._selected_index, len(ordered) - 1)
        self._selected_key = ordered[index].process_key
        self._selected_index = index
        return index

    def _move(self, delta: int) -> None:
        ordered = self._ordered()
        if not ordered:
            return
        current = self._position(ordered)
        target = 0 if current < 0 else current + delta
        self._select(ordered, target)

    def _move_to(self, index: int) -> None:
        ordered = self._ordered()
        if ordered:
            self._select(ordered, index if index >= 0 else len(ordered) - 1)

    def _select(self, ordered: Sequence[ProcessInfo], index: int) -> None:
        index = max(0, min(index, len(ordered) - 1))
        self._selected_index = index
        self._selected_key = ordered[index].process_key

    def selected_process(self) -> ProcessInfo | None:
        ordered = self._ordered()
        position = self._position(ordered)
        return ordered[position] if position >= 0 else None

    # -- actions ----------------------------------------------------------------------------

    def _flash(self, message: str, style: str, *, seconds: float | None = _STATUS_SECONDS) -> None:
        expires = None if seconds is None else self._clock() + seconds
        with self._lock:
            self._status = _Status(Text(sanitize_display(message), style=style), expires)
            self._dirty = True

    def _open_stop(self) -> None:
        if self._responses is None:
            self._flash("Process actions are not available in this session.", "yellow")
            return
        process = self.selected_process()
        if process is None:
            self._flash("Select a process first (↑/↓), then press T to stop it.", "yellow")
            return
        verdict = self._responses.protection_of(process)
        if verdict.protected:
            # Record the refused request exactly as the CLI does; the OS is never touched.
            self._responses.act_on_process(
                ActionType.TERMINATE_PROCESS, process, reason=STOP_REASON
            )
        self._modal = _Modal(ModalKind.STOP, process=process, verdict=verdict)

    def _stop(self, process: ProcessInfo) -> None:
        if self._responses is None:
            return
        label = f"{process.name} (PID {process.pid})"
        try:
            action = self._responses.act_on_process(
                ActionType.TERMINATE_PROCESS, process, reason=STOP_REASON
            )
        except Exception as exc:  # never let an action crash the dashboard
            self._flash(f"Could not stop {label}: {exc}", "bold red")
            return
        if action.outcome is ActionOutcome.SUCCEEDED:
            self._flash(f"Stopped {label}.", "bold green")
        else:
            self._flash(f"Could not stop {label}: {action.error}", "bold red")

    def _open_trim(self) -> None:
        if self._responses is None or not self._responses.can_trim_memory:
            self._flash("Clear RAM is not available in this session.", "yellow")
            return
        if self._trim_thread is not None and self._trim_thread.is_alive():
            self._flash("Clear RAM is already running…", "yellow")
            return
        self._modal = _Modal(ModalKind.TRIM)

    def _start_trim(self) -> None:
        self._flash("Clearing RAM…", "bold yellow", seconds=None)
        self._trim_thread = threading.Thread(
            target=self._run_trim, name="winsentinel-clear-ram", daemon=True
        )
        self._trim_thread.start()

    def _run_trim(self) -> None:
        if self._responses is None:
            return
        try:
            action, result = self._responses.trim_memory(reason=TRIM_REASON)
        except Exception as exc:
            self._flash(f"Clear RAM failed: {exc}", "bold red")
            return
        if result is None or action.outcome is not ActionOutcome.SUCCEEDED:
            self._flash(f"Clear RAM failed: {action.error}", "bold red")
            return
        message = (
            f"Cleared RAM: freed {format_bytes(result.freed_bytes)} from "
            f"{result.trimmed} processes in {result.duration_seconds:.1f}s"
        )
        if result.denied:
            suffix = "need administrator" if not self._elevated else "are protected"
            message += f" · {result.denied} {suffix}"
        self._flash(message, "bold green")
        self._sample_system()

    # -- rendering --------------------------------------------------------------------------

    def _sample_system(self) -> None:
        self._cpu = psutil.cpu_percent()
        self._memory = psutil.virtual_memory()

    def render(self) -> RenderableType:
        if self._memory is None:
            self._sample_system()
        data = self._data()
        alert_by_key: dict[str, Alert] = {
            a.process_key: a
            for a in data.alerts
            if a.process_key and a.status not in TERMINAL_STATUSES
        }

        layout = Layout()
        layout.split_column(
            Layout(self._header(data), name="header", size=HEADER_ROWS),
            Layout(name="body"),
            Layout(self._footer(), name="footer", size=FOOTER_ROWS),
        )
        layout["body"].split_row(
            Layout(self._process_panel(data.processes, alert_by_key), name="left", ratio=3),
            Layout(name="right", ratio=2),
        )
        if self._modal is not None:
            layout["right"].update(self._modal_panel(self._modal))
        else:
            layout["right"].split_column(
                Layout(self._network_panel(data.connections, alert_by_key), name="net"),
                Layout(self._alert_panel(data.alerts), name="alerts"),
                Layout(self._events_panel(), name="events"),
            )
        return layout

    def _header(self, data: _Data) -> RenderableType:
        cpu = self._cpu or 0.0
        memory = self._memory
        active_alerts = sum(1 for a in data.alerts if a.status not in TERMINAL_STATUSES)
        critical = sum(
            1
            for a in data.alerts
            if a.severity is Severity.CRITICAL and a.status not in TERMINAL_STATUSES
        )
        uptime = int(self._clock() - self._started)

        title = Text()
        title.append(f" {TITLE} ", style="bold white on blue")
        title.append(f"  {SUBTITLE}", style="bold")
        title.append(f"   v{__version__}", style=colors.MUTED)
        title.append(
            "   PAUSED (lists frozen)" if self._options.paused else "   ● MONITORING",
            style="yellow" if self._options.paused else "green",
        )

        stats = Table.grid(expand=True)
        for _ in range(4):
            stats.add_column(ratio=1)
        alert_style = "bold red" if active_alerts else "green"
        stats.add_row(
            Text.assemble(("Processes  ", colors.MUTED), (str(len(data.processes)), "bold")),
            Text.assemble(("Connections  ", colors.MUTED), (str(len(data.connections)), "bold")),
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
        ordered = order_processes(processes, sort)
        rows = self._visible_rows()
        position = self._position(ordered)
        if position >= 0:
            if position < self._scroll:
                self._scroll = position
            elif position >= self._scroll + rows:
                self._scroll = position - rows + 1
        self._scroll = max(0, min(self._scroll, len(ordered) - rows))

        table = Table(box=None, expand=True, pad_edge=False, header_style=colors.HEADER)
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("PROCESS", no_wrap=True, ratio=2, overflow="ellipsis")
        table.add_column("USER", no_wrap=True, ratio=2, overflow="ellipsis")
        table.add_column("CPU%", justify="right", no_wrap=True)
        table.add_column("MEM", justify="right", no_wrap=True)
        table.add_column("RISK", no_wrap=True)
        for index, p in enumerate(ordered[self._scroll : self._scroll + rows], self._scroll):
            selected = index == position
            alert = alert_by_key.get(p.process_key)
            name_style = "bold red" if alert else ("red" if p.suspended else "")
            cpu_style = _load_style(p.cpu_percent or 0)
            user_style = colors.MUTED
            if selected:  # the row style supplies the colours; cell colours would fight it
                name_style = cpu_style = user_style = ""
            risk = (
                Text(
                    alert.severity.value,
                    style="" if selected else colors.SEVERITY_STYLES[alert.severity],
                )
                if alert
                else Text("-", style="" if selected else colors.MUTED)
            )
            table.add_row(
                str(p.pid),
                Text(sanitize_display(p.name), style=name_style),
                Text(sanitize_display(p.username or "-"), style=user_style),
                Text(format_percent(p.cpu_percent), style=cpu_style),
                format_bytes(p.working_set),
                risk,
                style=_SELECTED_STYLE if selected else None,
            )
        title = f"PROCESSES  (sort: {sort})"
        if position >= 0:
            title += f"  {position + 1}/{len(ordered)}"
        return Panel(table, title=title, title_align="left", border_style="cyan")

    def _modal_panel(self, modal: _Modal) -> RenderableType:
        if modal.kind is ModalKind.STOP and modal.process is not None:
            return self._stop_panel(modal.process, modal.verdict)
        return self._trim_panel()

    def _stop_panel(self, process: ProcessInfo, verdict: ProtectionVerdict | None) -> Panel:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=colors.LABEL, no_wrap=True)
        grid.add_column(overflow="fold")
        grid.add_row("PID", Text(str(process.pid)))
        grid.add_row("Process", Text(sanitize_display(process.name), style="bold"))
        grid.add_row("Path", Text(sanitize_display(process.exe or "<unknown>")))
        grid.add_row("User", Text(sanitize_display(process.username or "-")))
        grid.add_row("Memory", Text(format_bytes(process.working_set)))
        parts: list[RenderableType] = []
        if verdict is not None and verdict.protected:
            parts += [
                Text("This process is protected and cannot be stopped.", style="bold red"),
                Text(""),
                grid,
                Text(""),
                Text(sanitize_display(f"Reason: {verdict.reason}."), style="red"),
                Text(
                    "Stopping it could crash Windows or sign you out. The refusal was recorded.",
                    style=colors.MUTED,
                ),
                Text(""),
                _key_hint([("Esc", "close")]),
            ]
            border = "red"
        else:
            parts += [
                Text("Stop this process?", style="bold"),
                Text(
                    "It is terminated immediately; unsaved work in it will be lost.",
                    style=colors.MUTED,
                ),
                Text(""),
                grid,
                Text(""),
                _key_hint([("Y", "stop process"), ("N", "cancel")]),
            ]
            border = "yellow"
        return Panel(
            Align.center(Group(*parts), vertical="middle"),
            title="STOP PROCESS",
            title_align="left",
            border_style=border,
        )

    def _trim_panel(self) -> Panel:
        memory = self._memory
        lines: list[RenderableType] = [
            Text("Clear RAM?", style="bold"),
            Text(""),
            Text("Trims the working set of every process you are allowed to access:"),
            Text("• frees physical RAM immediately; nothing is closed or deleted", style="green"),
            Text(
                "• programs page memory back in when they need it, so they may be briefly slower",
                style="yellow",
            ),
        ]
        if not self._elevated:
            lines.append(
                Text(
                    "• as a standard user, only your own processes can be trimmed",
                    style=colors.MUTED,
                )
            )
        if memory is not None:
            lines += [
                Text(""),
                Text(
                    f"RAM in use now: {format_bytes(memory.used)} of "
                    f"{format_bytes(memory.total)} ({memory.percent:.0f}%)"
                ),
            ]
        lines += [Text(""), _key_hint([("Y", "clear RAM"), ("N", "cancel")])]
        return Panel(
            Align.center(Group(*lines), vertical="middle"),
            title="CLEAR RAM",
            title_align="left",
            border_style="yellow",
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
        events = list(self._recents.events)
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
        with self._lock:
            status = self._status
            expires = None if status is None else status.expires_at
            if expires is not None and self._clock() >= expires:
                self._status = status = None
        status_line = (
            status.text
            if status is not None
            else Text("Select a process with ↑/↓ to stop it.", style=colors.MUTED)
        )
        keys = _key_hint(
            [
                ("↑↓", "select"),
                ("T", "stop"),
                ("C", "clear RAM"),
                ("P/M/N", "sort"),
                ("L", "loopback"),
                ("Space", "pause"),
                ("Q", "quit"),
            ]
        )
        return Group(Align.center(status_line), Align.center(keys))


def _key_hint(keys: Sequence[tuple[str, str]]) -> Text:
    text = Text()
    for key, label in keys:
        text.append(f" {key} ", style="bold black on cyan")
        text.append(f" {label}  ", style=colors.MUTED)
    return text


def _load_style(percent: float) -> str:
    if percent >= 80:
        return "bold red"
    if percent >= 50:
        return "yellow"
    return "green"


def _format_uptime(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"
