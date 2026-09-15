"""Structured, injection-safe logging.

Format (one record per line, ``key=value`` pairs after the level)::

    2026-09-15T11:32:04.123Z INFO winsentinel.monitors event=PROCESS_STARTED pid=4832 name=x.exe

Why key=value and not JSON? It is grep-friendly on Windows without extra tools and still
trivially machine-parsable. JSON export for SIEMs is a roadmap item.

Log injection: process names, command lines and paths are attacker-controlled. A process named
``evil.exe\\n2026-... INFO event=ALL_CLEAR`` would forge a log line. :class:`SafeFormatter`
escapes CR/LF and other control characters in the *final* message, so no argument can break the
one-record-per-line invariant.

Logs go to **stderr** so that ``--json`` output on stdout remains parseable.
"""

from __future__ import annotations

import logging
import re
import sys
import time
from typing import Final

_CONTROL_CHARS: Final = re.compile(r"[\x00-\x1f\x7f]")
_ESCAPES: Final = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def sanitize_log_value(value: object) -> str:
    """Escape control characters so a value cannot span or forge log lines."""
    return _CONTROL_CHARS.sub(
        lambda m: _ESCAPES.get(m.group(), f"\\x{ord(m.group()):02x}"), str(value)
    )


class SafeFormatter(logging.Formatter):
    def converter(self, timestamp: float | None) -> time.struct_time:
        """Timestamps in UTC (the ``Z`` suffix in the format), never local time."""
        return time.gmtime(timestamp)

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 (stdlib API name)
        record.message = sanitize_log_value(record.message)
        return super().formatMessage(record)

    def formatException(self, ei: object) -> str:  # noqa: N802
        # Tracebacks legitimately span lines; indent continuation lines so they cannot be
        # mistaken for new records.
        text = super().formatException(ei)  # type: ignore[arg-type]
        return "\n".join("    " + line for line in text.splitlines())


def configure_logging(level: str = "INFO", *, verbose: bool = False, quiet: bool = False) -> None:
    """Configure the root ``winsentinel`` logger (idempotent)."""
    effective = "DEBUG" if verbose else ("ERROR" if quiet else level)
    logger = logging.getLogger("winsentinel")
    logger.setLevel(effective)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(SafeFormatter())
    logger.addHandler(handler)
