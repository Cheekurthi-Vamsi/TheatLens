from __future__ import annotations

from fixtures.detection import proc
from fixtures.fakes import minutes
from threatlens.core.models import ActionOutcome, ActionType, IntegrityLevel, ProcessInfo
from threatlens.response.firewall_control import (
    CommandResult,
    FirewallController,
    FirewallError,
    block_ip_spec,
    block_port_spec,
)
from threatlens.response.process_control import (
    ProcessActionFailedError,
    ProcessController,
    ProcessIdentityChangedError,
)
from threatlens.response.protection import ProtectionPolicy
from threatlens.response.response_manager import ResponseManager
from threatlens.utils import windows


class FakeCollector:
    def __init__(self, processes: dict[int, ProcessInfo]) -> None:
        self._processes = processes

    def collect_pid(self, pid: int) -> ProcessInfo:
        from threatlens.errors import ProcessNotFoundError

        if pid not in self._processes:
            raise ProcessNotFoundError(pid)
        return self._processes[pid]


class RecordingControl:
    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list[tuple[str, int]] = []
        self._fail = fail

    def suspend(self, pid: int) -> None:
        self._do("suspend", pid)

    def resume(self, pid: int) -> None:
        self._do("resume", pid)

    def terminate(self, pid: int) -> None:
        self._do("terminate", pid)

    def _do(self, action: str, pid: int) -> None:
        self.calls.append((action, pid))
        if self._fail is not None:
            raise self._fail


def controller(process: ProcessInfo, control: RecordingControl) -> ProcessController:
    return ProcessController(FakeCollector({process.pid: process}), control)  # type: ignore[arg-type]


class TestProcessController:
    def test_verifies_identity_before_acting(self) -> None:
        process = proc(4832, "tool.exe", created=minutes(1))
        control = RecordingControl()
        ProcessController(FakeCollector({4832: process}), control).suspend(
            4832, process.process_key
        )  # type: ignore[arg-type]
        assert control.calls == [("suspend", 4832)]

    def test_refuses_when_pid_reused(self) -> None:
        process = proc(4832, "tool.exe", created=minutes(1))
        control = RecordingControl()
        c = ProcessController(FakeCollector({4832: process}), control)  # type: ignore[arg-type]
        try:
            c.terminate(4832, "4832:999")  # different creation time
            raise AssertionError("should have refused")
        except ProcessIdentityChangedError:
            pass
        assert control.calls == []  # never touched the process

    def test_access_denied_becomes_action_failed(self) -> None:
        process = proc(4832, "tool.exe", created=minutes(1))
        denied = OSError(5, "Access is denied")
        denied.winerror = windows.ERROR_ACCESS_DENIED  # type: ignore[attr-defined]
        c = ProcessController(FakeCollector({4832: process}), RecordingControl(fail=denied))  # type: ignore[arg-type]
        try:
            c.terminate(4832, process.process_key)
            raise AssertionError
        except ProcessActionFailedError as exc:
            assert "access denied" in str(exc)


class TestProtection:
    def test_kernel_and_named_processes_are_protected(self) -> None:
        policy = ProtectionPolicy(frozenset({"lsass.exe"}), own_pid=1)
        assert policy.evaluate(proc(4, "System", created=None)).protected
        assert policy.evaluate(proc(500, "lsass.exe", created=minutes(1))).protected
        system = proc(600, "svc.exe", created=minutes(1), integrity_level=IntegrityLevel.SYSTEM)
        assert policy.evaluate(system).protected
        assert policy.evaluate(proc(1, "threatlens.exe", created=minutes(1))).protected  # own pid

    def test_ordinary_process_is_not_protected(self) -> None:
        policy = ProtectionPolicy(frozenset(), own_pid=1)
        verdict = policy.evaluate(proc(4832, "tool.exe", created=minutes(1)))
        assert not verdict.protected


class TestResponseManager:
    def make(
        self,
        process: ProcessInfo,
        control: RecordingControl,
        *,
        protected: frozenset[str] = frozenset(),
    ) -> tuple[ResponseManager, list]:  # type: ignore[type-arg]
        audited: list = []
        manager = ResponseManager(
            controller(process, control),
            ProtectionPolicy(protected, own_pid=1),
            audit=audited.append,
            requested_by="tester",
        )
        return manager, audited

    def test_successful_terminate_is_recorded(self) -> None:
        process = proc(4832, "tool.exe", created=minutes(1))
        control = RecordingControl()
        manager, audited = self.make(process, control)
        action = manager.act_on_process(ActionType.TERMINATE_PROCESS, process, reason="unwanted")
        assert action.outcome is ActionOutcome.SUCCEEDED
        assert control.calls == [("terminate", 4832)]
        assert audited == [action] and audited[0].requested_by == "tester"

    def test_protected_process_is_denied_and_recorded(self) -> None:
        process = proc(500, "lsass.exe", created=minutes(1))
        control = RecordingControl()
        manager, audited = self.make(process, control, protected=frozenset({"lsass.exe"}))
        action = manager.act_on_process(ActionType.TERMINATE_PROCESS, process, reason="x")
        assert action.outcome is ActionOutcome.DENIED_BY_POLICY
        assert control.calls == []  # OS action never attempted
        assert audited and "protected" in (action.error or "")

    def test_force_protected_overrides(self) -> None:
        process = proc(500, "lsass.exe", created=minutes(1))
        control = RecordingControl()
        manager, _ = self.make(process, control, protected=frozenset({"lsass.exe"}))
        action = manager.act_on_process(
            ActionType.TERMINATE_PROCESS, process, reason="x", force_protected=True
        )
        assert action.outcome is ActionOutcome.SUCCEEDED and control.calls == [("terminate", 500)]

    def test_resume_ignores_protection(self) -> None:
        process = proc(500, "lsass.exe", created=minutes(1))
        control = RecordingControl()
        manager, _ = self.make(process, control, protected=frozenset({"lsass.exe"}))
        action = manager.act_on_process(ActionType.RESUME_PROCESS, process, reason="x")
        assert action.outcome is ActionOutcome.SUCCEEDED


class FakeBackend:
    def __init__(self, *results: CommandResult) -> None:
        self._results = list(results)
        self.commands: list[list[str]] = []

    def run(self, args: list[str]) -> CommandResult:
        self.commands.append(args)
        return self._results.pop(0) if self._results else CommandResult(0, "Ok.\n", "")


class TestFirewall:
    def test_block_ip_builds_outbound_rule(self) -> None:
        spec = block_ip_spec("93.184.216.34")
        assert spec.rule_name == "ThreatLens:ip:93.184.216.34"
        assert "action=block" in spec.netsh_args and "remoteip=93.184.216.34" in spec.netsh_args
        assert "dir=out" in spec.netsh_args

    def test_add_and_remove_roundtrip(self) -> None:
        backend = FakeBackend(CommandResult(0, "Ok.\n", ""), CommandResult(0, "Ok.\n", ""))
        controller = FirewallController(backend)
        controller.add(block_port_spec(4444, "tcp"))
        controller.remove("ThreatLens:port:TCP-4444")
        assert backend.commands[0][:4] == ["advfirewall", "firewall", "add", "rule"]
        assert backend.commands[1][:4] == ["advfirewall", "firewall", "delete", "rule"]

    def test_refuses_to_remove_foreign_rule(self) -> None:
        try:
            FirewallController(FakeBackend()).remove("Some Other Rule")
            raise AssertionError
        except FirewallError as exc:
            assert "refusing" in str(exc)

    def test_elevation_error_is_explained(self) -> None:
        backend = FakeBackend(CommandResult(1, "", "The requested operation requires elevation."))
        try:
            FirewallController(backend).add(block_ip_spec("1.1.1.1"))
            raise AssertionError
        except FirewallError as exc:
            assert "administrator" in str(exc)

    def test_bad_protocol_rejected(self) -> None:
        try:
            block_port_spec(80, "icmp")
            raise AssertionError
        except FirewallError:
            pass
