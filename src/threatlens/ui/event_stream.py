"""Line-oriented live event stream for ``threatlens monitor`` (human or JSON Lines).

All printing happens on the bus dispatcher thread (subscribers run sequentially there), so lines
never interleave. Every untrusted value passes through :func:`sanitize_display`.
"""

from __future__ import annotations

import sys
from collections.abc import Collection, Mapping
from typing import Any, Final, TextIO

from rich.console import Console
from rich.text import Text

from threatlens.core.models import AddressScope, Alert, DetectionResult, EventType, SecurityEvent
from threatlens.ui import colors
from threatlens.ui.alert_views import alert_stream_text
from threatlens.ui.detection_views import detection_stream_text
from threatlens.ui.formatting import sanitize_display
from threatlens.ui.json_output import json_line
from threatlens.utils.networking import format_endpoint
from threatlens.utils.time import format_clock

CATEGORY_EVENTS: Final[dict[str, frozenset[EventType]]] = {
    "process": frozenset(
        {EventType.PROCESS_STARTED, EventType.PROCESS_STOPPED, EventType.PROCESS_CHANGED}
    ),
    "network": frozenset(
        {
            EventType.CONNECTION_OPENED,
            EventType.CONNECTION_CLOSED,
            EventType.LISTENER_OPENED,
            EventType.LISTENER_CLOSED,
        }
    ),
    "health": frozenset({EventType.COLLECTOR_STATUS}),
    "inventory": frozenset(
        {
            EventType.PROCESS_DISCOVERED,
            EventType.CONNECTION_DISCOVERED,
            EventType.LISTENER_DISCOVERED,
        }
    ),
    "persistence": frozenset(
        {
            EventType.PERSISTENCE_ADDED,
            EventType.PERSISTENCE_REMOVED,
            EventType.PERSISTENCE_CHANGED,
        }
    ),
    "file": frozenset(
        {
            EventType.FILE_CREATED,
            EventType.FILE_DELETED,
            EventType.FILE_RENAMED,
            EventType.FILE_MODIFIED,
        }
    ),
    "enrichment": frozenset({EventType.PROCESS_ENRICHED}),
}
ALL_CATEGORIES: Final = (*CATEGORY_EVENTS, "detections", "alerts")
DEFAULT_CATEGORIES: Final = frozenset(
    {"process", "network", "persistence", "file", "health", "detections", "alerts"}
)

_EVENT_STYLES: Final[dict[EventType, str]] = {
    EventType.PROCESS_STARTED: "green",
    EventType.PROCESS_STOPPED: colors.MUTED,
    EventType.PROCESS_CHANGED: "yellow",
    EventType.PROCESS_ENRICHED: "cyan",
    EventType.CONNECTION_OPENED: "blue",
    EventType.CONNECTION_CLOSED: colors.MUTED,
    EventType.LISTENER_OPENED: "magenta",
    EventType.LISTENER_CLOSED: colors.MUTED,
    EventType.FILE_CREATED: "green",
    EventType.FILE_DELETED: colors.MUTED,
    EventType.FILE_RENAMED: "yellow",
    EventType.PERSISTENCE_ADDED: "bold magenta",
    EventType.PERSISTENCE_REMOVED: colors.MUTED,
    EventType.PERSISTENCE_CHANGED: "yellow",
    EventType.COLLECTOR_STATUS: "bold yellow",
}
_TYPE_WIDTH: Final = 20


def _s(value: object) -> str:
    return sanitize_display(str(value))


def _process(name: object, pid: int | None) -> Text:
    text = Text(_s(name) if name else "<unattributed>", style="bold" if name else colors.MUTED)
    if pid is not None:
        text.append(f" ({pid})", style=colors.MUTED)
    return text


def _socket_summary(data: Mapping[str, Any]) -> Text:
    text = Text(f"{data.get('protocol', '?')} ")
    text.append(format_endpoint(data.get("local_address"), data.get("local_port")))
    if data.get("remote_address") is not None:
        text.append(" ← " if data.get("direction") == "INBOUND" else " → ", style=colors.MUTED)
        remote_scope = data.get("remote_scope")
        style = "bold yellow" if remote_scope == AddressScope.PUBLIC.value else ""
        text.append(
            format_endpoint(data.get("remote_address"), data.get("remote_port")), style=style
        )
    text.append(f"  {data.get('state', '')}", style=colors.MUTED)
    scope = data.get("remote_scope") or data.get("local_scope")
    if scope:
        text.append(f"  {scope}", style=colors.MUTED)
    return text


def format_event(event: SecurityEvent) -> Text:
    """Render one event as a single line. Pure function (tested)."""
    data = event.data
    line = Text(format_clock(event.timestamp), style=colors.MUTED)
    line.append("  ")
    line.append(
        event.event_type.value.ljust(_TYPE_WIDTH), style=_EVENT_STYLES.get(event.event_type, "")
    )
    kind = event.event_type

    if kind is EventType.COLLECTOR_STATUS:
        line.append(
            f"{_s(data.get('component'))}: {data.get('previous_status')} → {data.get('status')}"
        )
        if data.get("last_error"):
            line.append(f"  {_s(data['last_error'])}", style=colors.WARNING)
        return line

    if kind.value.startswith("FILE_"):
        line.append_text(_process(data.get("name"), None))
        line.append(f"  {_s(data.get('path'))}", style=colors.MUTED)
        if data.get("from"):
            line.append(f"  (from {_s(data['from'])})", style=colors.MUTED)
        return line
    if kind.value.startswith("PERSISTENCE_"):
        line.append_text(_process(data.get("name"), None))
        line.append(f"  {_s(data.get('kind'))}", style="magenta")
        if data.get("executable"):
            line.append(f"  {_s(data['executable'])}", style=colors.MUTED)
        return line

    name = data.get("name", data.get("process"))
    line.append_text(_process(name, event.pid))

    if kind in (EventType.PROCESS_STARTED, EventType.PROCESS_DISCOVERED):
        if data.get("parent_name"):
            line.append("  ← ", style=colors.MUTED)
            line.append(_s(data["parent_name"]))
        if data.get("username"):
            line.append(f"  {_s(data['username'])}", style=colors.MUTED)
        if data.get("exe"):
            line.append(f"  {_s(data['exe'])}", style=colors.MUTED)
    elif kind is EventType.PROCESS_STOPPED:
        lifetime = data.get("max_lifetime_seconds")
        if lifetime is not None:
            line.append(f"  ran ≤ {lifetime:.1f}s", style=colors.MUTED)
    elif kind is EventType.PROCESS_CHANGED:
        for field, (old, new) in dict(data.get("changed", {})).items():
            line.append(f"  {_s(field)}: {old} → {new}")
    elif kind is EventType.PROCESS_ENRICHED:
        status = data.get("signature_status") or "?"
        line.append(f"  {status}", style="green" if status == "VALID" else "yellow")
        if data.get("signer"):
            line.append(f" ({_s(data['signer'])})", style=colors.MUTED)
        if data.get("sha256"):
            line.append(f"  sha256:{str(data['sha256'])[:16]}…", style=colors.MUTED)
    else:
        line.append("  ")
        line.append_text(_socket_summary(data))
        if data.get("attribution") not in (None, "ATTRIBUTED"):
            line.append(f"  [{data['attribution']}]", style=colors.MUTED)
    return line


class EventStreamPrinter:
    """Bus subscriber that prints filtered events."""

    def __init__(
        self,
        console: Console,
        *,
        categories: Collection[str] = DEFAULT_CATEGORIES,
        show_loopback: bool = False,
        json_lines: bool = False,
        stream: TextIO | None = None,
    ) -> None:
        self._console = console
        self._json = json_lines
        self._stream = stream or sys.stdout
        self._show_loopback = show_loopback
        self._show_detections = "detections" in categories
        self._show_alerts = "alerts" in categories
        self._event_types: frozenset[EventType] = frozenset().union(
            *(CATEGORY_EVENTS[c] for c in categories if c in CATEGORY_EVENTS)
        )
        self.printed = 0

    @property
    def event_types(self) -> frozenset[EventType]:
        return self._event_types

    def wants(self, event: SecurityEvent) -> bool:
        if event.event_type not in self._event_types:
            return False
        is_loopback = event.data.get("remote_scope") == AddressScope.LOOPBACK.value
        return self._show_loopback or not is_loopback

    def on_detection(self, result: DetectionResult) -> None:
        if not self._show_detections:
            return
        self.printed += 1
        if self._json:
            self._stream.write(json_line({"kind": "detection", "detection": result}) + "\n")
            self._stream.flush()
        else:
            self._console.print(detection_stream_text(result), soft_wrap=True, highlight=False)

    def on_alert(self, alert: Alert) -> None:
        if not self._show_alerts:
            return
        self.printed += 1
        if self._json:
            self._stream.write(json_line({"kind": "alert", "alert": alert}) + "\n")
            self._stream.flush()
        else:
            self._console.print(alert_stream_text(alert), soft_wrap=True, highlight=False)

    def on_event(self, event: SecurityEvent) -> None:
        if not self.wants(event):
            return
        self.printed += 1
        if self._json:
            self._stream.write(json_line({"kind": "event", "event": event}) + "\n")
            self._stream.flush()
        else:
            self._console.print(format_event(event), soft_wrap=True, highlight=False)
