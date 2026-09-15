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
from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.collectors.process_collector import ProcessCollector
from winsentinel.config import Config
from winsentinel.core.engine import Engine
from winsentinel.detection.alerting import AlertManager
from winsentinel.detection.engine import DetectionEngine
from winsentinel.detection.rules import build_rules
from winsentinel.detection.settings import DetectionSettings
from winsentinel.ui.dashboard import Dashboard
from winsentinel.ui.keyreader import KeyReader


def build() -> tuple[Dashboard, Engine, Console]:
    clock = FakeClock()

    def collector() -> ProcessCollector:
        source = FakeSource(
            [
                entry(4, ppid=0, name="System"),
                entry(100, name="chrome.exe"),
                entry(200, name="svchost.exe"),
            ]
        )
        return ProcessCollector(
            source, FakeInspector(), clock=clock.now, monotonic=clock.monotonic, cpu_count=2
        )

    sockets = FakeSocketSource([socket_entry(100, "10.0.0.5", 50000, "93.184.216.34", 443)])
    engine = Engine(
        Config(),
        process_collector=collector(),
        network_collector=NetworkCollector(sockets, clock=clock.now),
        attribution_collector=collector(),
        enricher=FakeEnricher(),  # type: ignore[arg-type]
        clock=clock.now,
    )
    settings = DetectionSettings.from_config(Config())
    detection = DetectionEngine(build_rules(settings), engine.state)
    alerts = AlertManager(40, running_check=engine.state.is_running)
    detection.subscribe(alerts.handle)
    engine.subscribe("detection", detection.handle, detection.event_types)
    console = Console(file=io.StringIO(), width=120, height=40, force_terminal=False)
    dashboard = Dashboard(console, engine, detection, alerts, elevated=False, refresh=1.0)
    engine.subscribe("dashboard", dashboard.on_event)
    return dashboard, engine, console


def test_dashboard_renders_populated_state() -> None:
    dashboard, engine, console = build()
    engine.run_cycle()  # populate state and recents
    console.print(dashboard.render())
    output = console.file.getvalue()  # type: ignore[attr-defined]
    assert "THREATLENS" in output
    assert "PROCESSES" in output and "NETWORK" in output and "ALERTS" in output
    assert "chrome.exe" in output


def test_dashboard_renders_before_any_data() -> None:
    dashboard, _engine, console = build()
    console.print(dashboard.render())  # must not raise on empty state
    assert "THREATLENS" in console.file.getvalue()  # type: ignore[attr-defined]


class FakeKeys(KeyReader):
    def __init__(self, keys: list[str]) -> None:
        super().__init__()
        self._keys = keys

    def get(self) -> str | None:
        return self._keys.pop(0) if self._keys else None


def test_key_handling_changes_options_and_quits() -> None:
    dashboard, _engine, _console = build()
    assert dashboard._handle_keys(FakeKeys(["m"])) is True
    assert dashboard._options.process_sort == "memory"
    assert dashboard._handle_keys(FakeKeys(["l"])) is True
    assert dashboard._options.show_loopback is True
    assert dashboard._handle_keys(FakeKeys(["q"])) is False
