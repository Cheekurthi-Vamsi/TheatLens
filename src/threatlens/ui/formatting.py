"""Human-friendly formatting helpers (pure functions)."""

from __future__ import annotations

import re
from typing import Final

from threatlens.core.models import FieldIssue, ProcessInfo

# C0 controls (incl. ESC), DEL, C1 controls, and Unicode bidirectional formatting characters.
# ESC/C1 can drive the terminal (OSC title changes, cursor movement, hyperlinks). Bidi overrides
# can visually disguise names, e.g. "invoice‮txt.exe" renders as "invoiceexe.txt".
_UNSAFE_DISPLAY: Final = re.compile(r"[\x00-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def sanitize_display(value: str) -> str:
    """Make untrusted text safe for a terminal while keeping the anomaly *visible*.

    Characters are escaped rather than removed: a process name containing an RLO override or an
    escape sequence is itself suspicious, and the analyst should see that it was there.
    """
    return _UNSAFE_DISPLAY.sub(
        lambda m: (
            f"\\u{ord(m.group()):04x}" if ord(m.group()) > 0xFF else f"\\x{ord(m.group()):02x}"
        ),
        value,
    )


_UNITS: Final = ("B", "KB", "MB", "GB", "TB")
_BYTES_PER_UNIT: Final = 1024

ISSUE_TEXT: Final[dict[FieldIssue, str]] = {
    FieldIssue.ACCESS_DENIED: "access denied",
    FieldIssue.PROCESS_EXITED: "process exited",
    FieldIssue.NOT_APPLICABLE: "n/a",
    FieldIssue.TOO_LARGE: "file too large",
    FieldIssue.ERROR: "read error",
}


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in _UNITS:
        if size < _BYTES_PER_UNIT or unit == _UNITS[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= _BYTES_PER_UNIT
    raise AssertionError("unreachable")


def format_percent(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}"


def field_or_reason(process: ProcessInfo, field: str, value: object | None) -> tuple[str, bool]:
    """Return ``(display_text, is_placeholder)`` for a possibly-unavailable field."""
    if value not in (None, ""):
        return sanitize_display(str(value)), False
    issue = process.unavailable.get(field)
    if issue is None:
        return "-", True
    return f"<{ISSUE_TEXT[issue]}>", True


def truncate_middle(text: str, width: int) -> str:
    """Shorten long paths keeping both ends (the file name is usually the useful part)."""
    if width < 5 or len(text) <= width:
        return text
    keep = width - 1
    head = keep // 3
    tail = keep - head
    return f"{text[:head]}…{text[-tail:]}"
