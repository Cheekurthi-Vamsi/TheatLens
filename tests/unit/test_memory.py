from __future__ import annotations

import pytest

from threatlens.core.models import ActionOutcome, ActionType, ResponseAction
from threatlens.errors import ThreatLensError
from threatlens.response.memory import MemoryTrimmer
from threatlens.response.process_control import ProcessController
from threatlens.response.protection import ProtectionPolicy
from threatlens.response.response_manager import ResponseManager
from threatlens.utils import windows


def os_error(winerror: int) -> OSError:
    error = OSError(winerror, "error")
    error.winerror = winerror  # type: ignore[attr-defined]
    return error


def trimmer(
    outcomes: dict[int, OSError | None], used: tuple[int, int] = (8_000, 5_000)
) -> tuple[MemoryTrimmer, list[int]]:
    attempted: list[int] = []
    readings = iter(used)

    def trim(pid: int) -> None:
        attempted.append(pid)
        error = outcomes[pid]
        if error is not None:
            raise error

    return (
        MemoryTrimmer(trim=trim, pids=lambda: list(outcomes), used_bytes=lambda: next(readings)),
        attempted,
    )


def test_counts_trimmed_denied_and_gone_and_skips_pseudo_processes() -> None:
    subject, attempted = trimmer(
        {
            0: None,
            4: None,
            100: None,
            200: os_error(windows.ERROR_ACCESS_DENIED),
            300: os_error(windows.ERROR_INVALID_PARAMETER),  # exited
            400: None,
        }
    )
    result = subject.trim_all()
    assert attempted == [100, 200, 300, 400]
    assert (result.trimmed, result.denied, result.gone) == (2, 1, 1)
    assert result.freed_bytes == 3_000


def test_freed_is_never_negative() -> None:
    subject, _ = trimmer({100: None}, used=(5_000, 6_000))  # something else allocated meanwhile
    assert subject.trim_all().freed_bytes == 0


def manager(memory: MemoryTrimmer | None, audit: list[ResponseAction]) -> ResponseManager:
    return ResponseManager(
        ProcessController(),
        ProtectionPolicy(frozenset(), own_pid=1),
        memory=memory,
        audit=audit.append,
        requested_by="tester",
    )


def test_trim_memory_is_audited_with_details() -> None:
    audit: list[ResponseAction] = []
    subject, _ = trimmer({100: None, 200: os_error(windows.ERROR_ACCESS_DENIED)})
    action, result = manager(subject, audit).trim_memory(reason="test")
    assert result is not None and action.outcome is ActionOutcome.SUCCEEDED
    assert action.action_type is ActionType.TRIM_WORKING_SETS
    assert action.details["trimmed"] == 1 and action.details["access_denied"] == 1
    assert audit == [action]


def test_trim_memory_fails_when_nothing_was_accessible() -> None:
    audit: list[ResponseAction] = []
    subject, _ = trimmer({100: os_error(windows.ERROR_ACCESS_DENIED)})
    action, _ = manager(subject, audit).trim_memory(reason="test")
    assert action.outcome is ActionOutcome.FAILED and action.error


def test_trim_memory_unavailable_without_trimmer() -> None:
    subject = manager(None, [])
    assert subject.can_trim_memory is False
    with pytest.raises(ThreatLensError):
        subject.trim_memory(reason="test")
