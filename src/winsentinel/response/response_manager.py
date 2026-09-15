"""Audited orchestration of response actions.

Every method returns a :class:`ResponseAction` recording exactly what happened — succeeded,
failed, or denied by the protected-process policy — and writes it to the audit log when a store
is provided. The CLI is responsible for showing the target and obtaining confirmation *before*
calling these; this layer enforces the safety policy and records the outcome.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable
from typing import Final

from winsentinel.core.models import ActionOutcome, ActionType, ProcessInfo, ResponseAction
from winsentinel.errors import WinSentinelError
from winsentinel.response.firewall_control import FirewallController, FirewallRuleSpec
from winsentinel.response.process_control import ProcessController
from winsentinel.response.protection import ProtectionPolicy

_PROCESS_ACTIONS: Final = {
    ActionType.SUSPEND_PROCESS: "suspend",
    ActionType.RESUME_PROCESS: "resume",
    ActionType.TERMINATE_PROCESS: "terminate",
}


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


class ResponseManager:
    def __init__(
        self,
        controller: ProcessController,
        policy: ProtectionPolicy,
        *,
        firewall: FirewallController | None = None,
        audit: Callable[[ResponseAction], None] | None = None,
        requested_by: str | None = None,
    ) -> None:
        self._controller = controller
        self._policy = policy
        self._firewall = firewall
        self._audit = audit
        self._requested_by = requested_by or current_user()

    def _record(self, action: ResponseAction) -> ResponseAction:
        if self._audit is not None:
            self._audit(action)
        return action

    # -- process actions --------------------------------------------------------------------

    def act_on_process(
        self,
        action_type: ActionType,
        process: ProcessInfo,
        *,
        reason: str,
        force_protected: bool = False,
    ) -> ResponseAction:
        verb = _PROCESS_ACTIONS[action_type]
        base = {
            "action_type": action_type,
            "target": f"{process.name} (PID {process.pid})",
            "process_key": process.process_key,
            "pid": process.pid,
            "reason": reason,
            "requested_by": self._requested_by,
            "details": {"exe": process.exe, "process_key": process.process_key},
        }
        # Resume is always safe (it only un-freezes); protection applies to suspend/terminate.
        if action_type is not ActionType.RESUME_PROCESS:
            verdict = self._policy.evaluate(process)
            if verdict.protected and not force_protected:
                return self._record(
                    ResponseAction(
                        outcome=ActionOutcome.DENIED_BY_POLICY,
                        error=f"protected process: {verdict.reason}",
                        **base,
                    )
                )
        try:
            operation = getattr(self._controller, verb)
            operation(process.pid, process.process_key)
        except WinSentinelError as exc:
            return self._record(
                ResponseAction(outcome=ActionOutcome.FAILED, error=str(exc), **base)
            )
        return self._record(ResponseAction(outcome=ActionOutcome.SUCCEEDED, **base))

    def protection_of(self, process: ProcessInfo) -> object:
        return self._policy.evaluate(process)

    # -- firewall ---------------------------------------------------------------------------

    def firewall_block(
        self, spec: FirewallRuleSpec, action_type: ActionType, *, reason: str
    ) -> ResponseAction:
        if self._firewall is None:
            raise WinSentinelError("firewall control is not available")
        base = {
            "action_type": action_type,
            "target": spec.target,
            "reason": reason,
            "requested_by": self._requested_by,
            "details": {
                "rule_name": spec.rule_name,
                "target_type": spec.target_type,
                "direction": spec.direction,
            },
        }
        try:
            self._firewall.add(spec)
        except WinSentinelError as exc:
            return self._record(
                ResponseAction(outcome=ActionOutcome.FAILED, error=str(exc), **base)
            )
        return self._record(ResponseAction(outcome=ActionOutcome.SUCCEEDED, **base))

    def firewall_unblock(self, rule_name: str, *, reason: str) -> ResponseAction:
        if self._firewall is None:
            raise WinSentinelError("firewall control is not available")
        base = {
            "action_type": ActionType.FIREWALL_UNBLOCK,
            "target": rule_name,
            "reason": reason,
            "requested_by": self._requested_by,
            "details": {"rule_name": rule_name},
        }
        try:
            self._firewall.remove(rule_name)
        except WinSentinelError as exc:
            return self._record(
                ResponseAction(outcome=ActionOutcome.FAILED, error=str(exc), **base)
            )
        return self._record(ResponseAction(outcome=ActionOutcome.SUCCEEDED, **base))
