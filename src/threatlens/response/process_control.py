"""Process suspend / resume / terminate with a PID-reuse safety guard.

The guard is the point of this module: Windows recycles PIDs, so between the moment the user
inspects PID 4832 and the moment they confirm a kill, PID 4832 could belong to a *different*
process. Every action therefore re-reads the process and refuses unless its identity
(``process_key`` = PID + creation time) still matches the one the user acted on.

This module performs the OS action only; the protected-process policy, confirmation and audit
logging live in :mod:`threatlens.response.response_manager`.
"""

from __future__ import annotations

from typing import Protocol

from threatlens.collectors.process_collector import ProcessCollector
from threatlens.core.models import ProcessInfo
from threatlens.errors import ProcessNotFoundError, ThreatLensError
from threatlens.utils import windows


class ProcessIdentityChangedError(ThreatLensError):
    """The PID no longer belongs to the process the user acted on (reuse or restart)."""


class ProcessActionFailedError(ThreatLensError):
    """The OS refused the action (access denied, protected process, etc.)."""


class OsProcessControl(Protocol):
    def suspend(self, pid: int) -> None: ...
    def resume(self, pid: int) -> None: ...
    def terminate(self, pid: int) -> None: ...


class Win32ProcessControl:
    def suspend(self, pid: int) -> None:
        windows.suspend_process(pid)

    def resume(self, pid: int) -> None:
        windows.resume_process(pid)

    def terminate(self, pid: int) -> None:
        windows.terminate_process(pid)


ACCESS_DENIED_HINT = (
    "access denied — you can only act on your own processes unless running as administrator, "
    "and protected (PPL) processes cannot be controlled even when elevated"
)


class ProcessController:
    def __init__(
        self, collector: ProcessCollector | None = None, control: OsProcessControl | None = None
    ) -> None:
        self._collector = collector or ProcessCollector()
        self._control = control or Win32ProcessControl()

    def current(self, pid: int) -> ProcessInfo:
        """Read the process now; raises :class:`ProcessNotFoundError` if it is gone."""
        return self._collector.collect_pid(pid)

    def _verify(self, pid: int, expected_key: str) -> ProcessInfo:
        current = self._collector.collect_pid(pid)
        if current.process_key != expected_key:
            raise ProcessIdentityChangedError(
                f"PID {pid} no longer refers to the same process (it exited and the PID was "
                f"reused, or it restarted). Re-inspect it before acting."
            )
        return current

    def _act(self, pid: int, expected_key: str, action: str) -> None:
        self._verify(pid, expected_key)
        operation = {
            "suspend": self._control.suspend,
            "resume": self._control.resume,
            "terminate": self._control.terminate,
        }[action]
        try:
            operation(pid)
        except ProcessNotFoundError:
            raise
        except OSError as exc:
            detail = (
                ACCESS_DENIED_HINT
                if getattr(exc, "winerror", None) == windows.ERROR_ACCESS_DENIED
                else str(exc)
            )
            raise ProcessActionFailedError(f"could not {action} PID {pid}: {detail}") from exc

    def suspend(self, pid: int, expected_key: str) -> None:
        self._act(pid, expected_key, "suspend")

    def resume(self, pid: int, expected_key: str) -> None:
        self._act(pid, expected_key, "resume")

    def terminate(self, pid: int, expected_key: str) -> None:
        self._act(pid, expected_key, "terminate")
