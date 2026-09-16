"""Privilege detection.

ThreatLens never requests elevation. It detects the current token's state so the CLI can tell
the user *why* some data is unavailable and what running elevated would add.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from threatlens.utils.windows import is_current_process_elevated, is_windows

logger = logging.getLogger(__name__)

ELEVATION_HINT = (
    "Running without administrator rights: command lines, usernames and integrity levels of "
    "processes owned by other users or SYSTEM are unavailable. Start the terminal with "
    "'Run as administrator' for fuller visibility. Protected processes (PPL) stay unreadable "
    "even when elevated."
)


@dataclass(frozen=True, slots=True)
class PrivilegeState:
    elevated: bool
    detection_failed: bool = False


def detect_privileges() -> PrivilegeState:
    """Return the elevation state; never raises."""
    if not is_windows():
        return PrivilegeState(elevated=False, detection_failed=True)
    try:
        return PrivilegeState(elevated=is_current_process_elevated())
    except OSError as exc:
        logger.warning("event=PRIVILEGE_DETECTION_FAILED error=%s", exc)
        return PrivilegeState(elevated=False, detection_failed=True)
