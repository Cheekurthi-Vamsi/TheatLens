"""Time helpers. All internal timestamps are timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

FILETIME_EPOCH_OFFSET: Final = 116_444_736_000_000_000  # 100ns intervals from 1601 to 1970
HUNDRED_NS_PER_SECOND: Final = 10_000_000


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def from_epoch(seconds: float) -> datetime | None:
    """Convert an epoch timestamp to aware UTC; ``0`` / negative means "not available".

    psutil and the kernel report ``0`` for pseudo processes such as *System*.
    """
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, tz=UTC)


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01 UTC) to aware UTC.

    Values at or before the Unix epoch are treated as "not set" — Windows uses 0 for that.
    """
    if filetime <= FILETIME_EPOCH_OFFSET:
        return None
    return from_epoch((filetime - FILETIME_EPOCH_OFFSET) / HUNDRED_NS_PER_SECOND)


def format_local(ts: datetime | None) -> str:
    """Render an aware timestamp in the machine's local timezone for humans."""
    if ts is None:
        return "-"
    return ts.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def format_clock(ts: datetime) -> str:
    """Local wall-clock time with milliseconds, for event streams."""
    local = ts.astimezone()
    return local.strftime("%H:%M:%S.") + f"{local.microsecond // 1000:03d}"


_DURATION_UNITS: Final = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> timedelta:
    """Parse ``30s``, ``15m``, ``2h``, ``7d``, ``1w`` (or a bare number of seconds)."""
    value = text.strip().lower()
    if not value:
        raise ValueError("empty duration")
    unit = value[-1]
    if unit in _DURATION_UNITS:
        number, factor = value[:-1], _DURATION_UNITS[unit]
    else:
        number, factor = value, 1
    try:
        amount = float(number)
    except ValueError:
        raise ValueError(f"invalid duration {text!r} (use e.g. 30s, 15m, 2h, 7d)") from None
    if amount < 0:
        raise ValueError("duration must not be negative")
    return timedelta(seconds=amount * factor)
