from __future__ import annotations

import io

from rich.console import Console

from fixtures.fakes import (
    FakeClock,
    FakeEnricher,
    FakeInspector,
    FakeSocketSource,
    FakeSource,
    entry,
    socket_entry,
)
from threatlens.collectors.network_collector import NetworkCollector
from threatlens.collectors.process_collector import ProcessCollector
from threatlens.config import Config
from threatlens.core.engine import Engine
from threatlens.core.models import ActionOutcome, ActionType, ProcessInfo, ResponseAction
from threatlens.detection.alerting import AlertManager
from threatlens.detection.engine import DetectionEngine
from threatlens.detection.rules import build_rules
from threatlens.detection.settings import DetectionSettings
from threatlens.errors import ProcessNotFoundError
from threatlens.response.memory import MemoryTrimmer
from threatlens.response.process_control import ProcessController
from threatlens.response.protection import ProtectionPolicy
from threatlens.response.response_manager import ResponseManager
from threatlens.ui.dashboard import Dashboard, ModalKind
from threatlens.ui.keyreader import KeyReader


class StateCollector:
    """collect_pid answers from the engine's state, as the real collector would from the OS."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def collect_pid(self, pid: int) -> ProcessInfo:
        for process in self._engine.state.processes():
            if process.pid == pid:
                return process
        raise ProcessNotFoundError(pid)


class RecordingControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def suspend(self, pid: int) -> None:
        self.calls.append(("suspend", pid))

    def resume(self, pid: int) -> None:
        self.calls.append(("resume", pid))

    def terminate(self, pid: int) -> None:
        self.calls.append(("terminate", pid))


class Harness:
    def __init__(self) -> None:
        clock = FakeClock()

        def collector() -> ProcessCollector:
            source = FakeSource(
                [
                    entry(4, ppid=0, name="System"),
                    entry(100, name="chrome.exe"),
                    entry(200, name="notepad.exe"),
                ]
            )
            return ProcessCollector(
                source, FakeInspector(), clock=clock.now, monotonic=clock.monotonic, cpu_count=2
            )

        sockets = FakeSocketSource([socket_entry(100, "10.0.0.5", 50000, "93.184.216.34", 443)])
        self.engine = Engine(
            Config(),
            process_collector=collector(),
            network_collector=NetworkCollector(sockets, clock=clock.now),
            attribution_collector=collector(),
            enricher=FakeEnricher(),  # type: ignore[arg-type]
            clock=clock.now,
        )
        settings = DetectionSettings.from_config(Config())
        detection = DetectionEngine(build_rules(settings), self.engine.state)
        alerts = AlertManager(40, running_check=self.engine.state.is_running)
        self.control = RecordingControl()
        self.audit: list[ResponseAction] = []
        self.trimmed: list[int] = []
        used = iter([6_000_000_000, 5_000_000_000])
        trimmer = MemoryTrimmer(
            trim=self.trimmed.append,
            pids=lambda: [0, 4, 100, 200],
            used_bytes=lambda: next(used),
        )
        responses = ResponseManager(
            ProcessController(StateCollector(self.engine), self.control),  # type: ignore[arg-type]
            ProtectionPolicy(frozenset(), own_pid=1),
            memory=trimmer,
            audit=self.audit.append,
            requested_by="tester",
        )
        self.console = Console(file=io.StringIO(), width=140, height=40, force_terminal=False)
        self.dashboard = Dashboard(
            self.console,
            self.engine,
            detection,
            alerts,
            elevated=False,
            refresh=1.0,
            responses=responses,
        )
        self.engine.subscribe("dashboard", self.dashboard.on_event)
        self.engine.run_cycle()

    def press(self, *keys: str) -> bool:
        return self.dashboard._handle_keys(FakeKeys(list(keys)))

    def screen(self) -> str:
        with self.console.capture() as capture:
            self.console.print(self.dashboard.render())
        return capture.get()


class FakeKeys(KeyReader):
    def __init__(self, keys: list[str]) -> None:
        super().__init__()
        self._keys = keys

    def get(self) -> str | None:
        return self._keys.pop(0) if self._keys else None


def test_dashboard_renders_populated_state() -> None:
    h = Harness()
    output = h.screen()
    assert "THREATLENS" in output
    assert "PROCESSES" in output and "NETWORK" in output and "ALERTS" in output
    assert "chrome.exe" in output and "clear RAM" in output


def test_key_handling_changes_options_and_quits() -> None:
    h = Harness()
    assert h.press("m") is True
    assert h.dashboard._options.process_sort == "memory"
    assert h.press("l") is True
    assert h.dashboard._options.show_loopback is True
    assert h.press("q") is False


def test_arrow_keys_select_and_selection_follows_the_process() -> None:
    h = Harness()
    assert h.dashboard.selected_process() is None  # nothing selected until the user navigates
    h.press("DOWN")
    assert h.dashboard.selected_process().pid == 4  # type: ignore[union-attr]
    h.press("DOWN", "DOWN", "DOWN")  # clamps at the last row
    assert h.dashboard.selected_process().pid == 200  # type: ignore[union-attr]
    h.press("n")  # re-sort by name: notepad.exe is now in a different row, still selected
    assert h.dashboard.selected_process().pid == 200  # type: ignore[union-attr]
    h.press("HOME")
    assert h.dashboard.selected_process().name == "chrome.exe"  # type: ignore[union-attr]
    assert "2/3" not in h.screen() and "1/3" in h.screen()


def test_stop_requires_a_selection() -> None:
    h = Harness()
    h.press("t")
    assert h.dashboard._modal is None
    assert "Select a process first" in h.screen()
    assert h.control.calls == []


def test_stop_confirmed_terminates_selected_process_and_audits() -> None:
    h = Harness()
    h.press("END", "t")  # notepad.exe
    assert h.dashboard._modal is not None and h.dashboard._modal.kind is ModalKind.STOP
    screen = h.screen()
    assert "STOP PROCESS" in screen and "notepad.exe" in screen
    assert h.control.calls == []  # nothing happens before confirmation
    h.press("y")
    assert h.control.calls == [("terminate", 200)]
    assert [(a.action_type, a.outcome) for a in h.audit] == [
        (ActionType.TERMINATE_PROCESS, ActionOutcome.SUCCEEDED)
    ]
    assert "Stopped notepad.exe (PID 200)" in h.screen()


def test_stop_cancelled_does_nothing_but_is_audited() -> None:
    h = Harness()
    h.press("END", "DELETE", "n")
    assert h.control.calls == []
    assert [a.outcome for a in h.audit] == [ActionOutcome.CANCELLED]
    assert h.dashboard._modal is None


def test_protected_process_is_refused_without_confirmation() -> None:
    h = Harness()
    h.press("DOWN", "t")  # System (PID 4)
    screen = h.screen()
    assert "protected and cannot be stopped" in screen
    h.press("y")  # there is nothing to confirm: this only closes the notice
    assert h.control.calls == []
    assert [a.outcome for a in h.audit] == [ActionOutcome.DENIED_BY_POLICY]
    assert h.dashboard._modal is None


def test_clear_ram_confirmed_runs_in_background_and_reports() -> None:
    h = Harness()
    h.press("c")
    assert "CLEAR RAM" in h.screen() and h.trimmed == []
    h.press("y")
    h.dashboard.wait_for_background_work(5)
    assert h.trimmed == [100, 200]  # kernel pseudo-processes are skipped
    (action,) = h.audit
    assert action.action_type is ActionType.TRIM_WORKING_SETS
    assert action.outcome is ActionOutcome.SUCCEEDED
    assert action.details["freed_bytes"] == 1_000_000_000
    assert "Cleared RAM: freed" in h.screen()


def test_clear_ram_cancel() -> None:
    h = Harness()
    h.press("c", "\x1b")
    assert h.trimmed == []
    assert [a.outcome for a in h.audit] == [ActionOutcome.CANCELLED]


def test_escape_closes_a_dialog_before_quitting() -> None:
    h = Harness()
    assert h.press("c", "\x1b") is True  # closes the dialog
    assert h.press("\x1b") is False  # now quits


def test_pause_freezes_lists() -> None:
    h = Harness()
    h.press(" ")
    frozen = h.dashboard._data()
    h.engine.run_cycle()
    assert h.dashboard._data() is frozen
    h.press(" ")
    assert h.dashboard._data() is not frozen


def test_dashboard_without_actions_explains() -> None:
    h = Harness()
    h.dashboard._responses = None
    h.press("DOWN", "t", "c")
    assert h.dashboard._modal is None
    assert "not available" in h.screen()
