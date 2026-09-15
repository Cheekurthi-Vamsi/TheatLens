"""Response-action models (Phase 10, docs/architecture.md §25)."""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import AwareDatetime, Field

from winsentinel.core.models.common import Frozen, Pid
from winsentinel.utils.time import utc_now


class ActionType(StrEnum):
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    RESUME_PROCESS = "RESUME_PROCESS"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    FIREWALL_BLOCK_IP = "FIREWALL_BLOCK_IP"
    FIREWALL_BLOCK_PORT = "FIREWALL_BLOCK_PORT"
    FIREWALL_BLOCK_PROCESS = "FIREWALL_BLOCK_PROCESS"
    FIREWALL_UNBLOCK = "FIREWALL_UNBLOCK"
    ALLOWLIST_ADD = "ALLOWLIST_ADD"
    ALLOWLIST_REMOVE = "ALLOWLIST_REMOVE"
    ALERT_STATUS_CHANGE = "ALERT_STATUS_CHANGE"
    BASELINE_CREATE = "BASELINE_CREATE"
    TRIM_WORKING_SETS = "TRIM_WORKING_SETS"


class ActionOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DENIED_BY_POLICY = "DENIED_BY_POLICY"


class ResponseAction(Frozen):
    """An audit record of something the user asked WinSentinel to do.

    Every state-changing action produces one of these, whether it succeeded, failed, was cancelled
    at the confirmation prompt, or was blocked by the protected-process policy.
    """

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: AwareDatetime = Field(default_factory=utc_now)
    action_type: ActionType
    target: str
    process_key: str | None = None
    pid: Pid | None = None
    reason: str = ""
    requested_by: str = ""
    outcome: ActionOutcome
    error: str | None = None
    reverses_action_id: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
