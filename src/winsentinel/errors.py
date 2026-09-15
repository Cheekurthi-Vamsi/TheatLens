"""Exception hierarchy and CLI exit codes.

Every error the CLI can surface maps to one exit code, so scripts consuming WinSentinel can
branch on the failure class without parsing messages.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes (documented in docs/architecture.md §13)."""

    OK = 0
    ERROR = 1
    USAGE = 2
    INSUFFICIENT_PRIVILEGES = 3
    NOT_FOUND = 4
    CANCELLED = 5
    BLOCKED_BY_POLICY = 6


class WinSentinelError(Exception):
    """Base class for all expected, user-reportable errors."""

    exit_code: ExitCode = ExitCode.ERROR


class ConfigError(WinSentinelError):
    """Configuration file is missing, unreadable, or invalid."""

    exit_code = ExitCode.USAGE


class InvalidInputError(WinSentinelError):
    """A user-supplied value (PID, IP, port, path) failed validation."""

    exit_code = ExitCode.USAGE


class ProcessNotFoundError(WinSentinelError):
    """The requested process does not exist (or exited during inspection)."""

    exit_code = ExitCode.NOT_FOUND

    def __init__(self, pid: int) -> None:
        super().__init__(f"No process with PID {pid} exists (it may have exited).")
        self.pid = pid


class InsufficientPrivilegesError(WinSentinelError):
    """The operation requires rights the current token does not hold."""

    exit_code = ExitCode.INSUFFICIENT_PRIVILEGES


class PlatformNotSupportedError(WinSentinelError):
    """A Windows-only API was invoked on another platform or an unsupported build."""


class CollectorUnavailableError(WinSentinelError):
    """A collector cannot produce data at all (distinct from partial data)."""
