from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixtures.fakes import (
    FakeClock,
    FakeDetails,
    FakeInspector,
    FakeSocketSource,
    FakeSource,
    entry,
    socket_entry,
)
from threatlens import cli
from threatlens.collectors.network_collector import NetworkCollector
from threatlens.collectors.process_collector import ProcessCollector, ProcessCollectorOptions
from threatlens.errors import ExitCode


@pytest.fixture
def fake_system(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Replace the OS layer with a small fixed process list and isolate config/app data."""
    source = FakeSource(
        [
            entry(4, ppid=0, name="System"),
            entry(1000, ppid=4, name="explorer.exe"),
            entry(2000, ppid=1000, name="tool.exe"),
        ]
    )
    inspector = FakeInspector(
        {
            2000: FakeDetails(
                exe=r"C:\Users\alice\Downloads\tool.exe",  # not a trusted location
                argv=["tool.exe", "--password", "hunter2"],
            )
        }
    )
    clock = FakeClock()

    def factory(
        *_: object, options: ProcessCollectorOptions | None = None, **__: object
    ) -> ProcessCollector:
        return ProcessCollector(
            source, inspector, options, clock=clock.now, monotonic=clock.monotonic, cpu_count=2
        )

    sockets = FakeSocketSource(
        [
            socket_entry(2000, "10.0.0.5", 50000, "93.184.216.34", 4444),
            socket_entry(1000, "0.0.0.0", 8080, state="LISTEN"),
            socket_entry(1000, "127.0.0.1", 50001, "127.0.0.1", 8080),
        ]
    )
    monkeypatch.setattr(cli, "ProcessCollector", factory)
    monkeypatch.setattr(cli, "NetworkCollector", lambda *_, **__: NetworkCollector(sockets))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("THREATLENS_CONFIG", raising=False)


def cli_actions() -> list[dict]:  # type: ignore[type-arg]
    """Audit rows from the database the CLI wrote (under the patched LOCALAPPDATA)."""
    from threatlens.config import Config
    from threatlens.storage.database import Database

    with Database(Config().general.resolved_database_path(), read_only=True) as db:
        return [dict(r) for r in db.query("SELECT * FROM actions")]


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> dict:  # type: ignore[type-arg]
    assert cli.main(list(argv)) == ExitCode.OK
    return json.loads(capsys.readouterr().out)  # type: ignore[no-any-return]


@pytest.mark.usefixtures("fake_system")
class TestCommands:
    def test_processes_json_flag_after_subcommand(self, capsys: pytest.CaptureFixture[str]) -> None:
        doc = run_json(capsys, "processes", "--json", "--sample", "0", "--sort", "pid")
        assert doc["schema"] == "threatlens.processes"
        assert doc["schema_version"] == 1
        assert [p["pid"] for p in doc["processes"]] == [4, 1000, 2000]

    def test_processes_json_flag_before_subcommand(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        doc = run_json(capsys, "--json", "processes", "--sample", "0", "--name", "TOOL")
        assert [p["name"] for p in doc["processes"]] == ["tool.exe"]

    def test_process_json_includes_lineage_and_redacted_cmdline(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        doc = run_json(capsys, "process", "2000", "--json", "--sample", "0", "--no-verify")
        assert doc["process"]["cmdline"] == ["tool.exe", "--password", "***REDACTED***"]
        assert [a["name"] for a in doc["ancestry"]] == ["explorer.exe", "System"]

    def test_process_not_found_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["process", "31337", "--sample", "0"]) == ExitCode.NOT_FOUND
        assert "31337" in capsys.readouterr().err

    def test_tree_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        doc = run_json(capsys, "tree", "--json")
        (system,) = doc["roots"]
        assert system["name"] == "System"
        assert system["children"][0]["children"][0]["name"] == "tool.exe"

    def test_human_output_renders(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["processes", "--sample", "0", "--no-color"]) == ExitCode.OK
        assert "explorer.exe" in capsys.readouterr().out

    def test_network_json_is_attributed_and_filterable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        doc = run_json(capsys, "network", "--json")
        assert doc["schema"] == "threatlens.network" and doc["total"] == 3
        external = run_json(capsys, "network", "--json", "--external")["connections"]
        assert [(c["process"], c["remote_port"], c["remote_scope"]) for c in external] == [
            ("tool.exe", 4444, "PUBLIC")
        ]
        listening = run_json(capsys, "network", "--json", "--listening")["connections"]
        assert [(c["process"], c["local_port"], c["direction"]) for c in listening] == [
            ("explorer.exe", 8080, "LISTENING")
        ]

    def test_connections_groups_by_process(self, capsys: pytest.CaptureFixture[str]) -> None:
        doc = run_json(capsys, "connections", "--json")
        grouped = {g["process"]["name"]: len(g["connections"]) for g in doc["processes"]}
        assert grouped == {"explorer.exe": 1, "tool.exe": 1}  # the listener is excluded

    def test_inspect_json_includes_owned_connections(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        doc = run_json(capsys, "inspect", "2000", "--json", "--sample", "0")
        assert doc["schema"] == "threatlens.inspect"
        assert [c["remote_port"] for c in doc["connections"]] == [4444]
        assert [a["name"] for a in doc["ancestry"]] == ["explorer.exe", "System"]

    def test_network_and_inspect_human_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["network", "--no-color"]) == ExitCode.OK
        assert cli.main(["connections", "--no-color"]) == ExitCode.OK
        assert cli.main(["inspect", "2000", "--no-color", "--sample", "0"]) == ExitCode.OK
        out = capsys.readouterr().out
        assert "93.184.216.34:4444" in out
        assert "EXTERNAL COMMUNICATION CHAINS" in out

    def test_monitor_json_lines_stream_and_clean_shutdown(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        argv = ["monitor", "--json", "--duration", "0.6", "--interval", "0.5", "--events", "all"]
        assert cli.main(argv) == ExitCode.OK
        lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        kinds = [line["kind"] for line in lines]
        assert kinds[-1] == "shutdown" and lines[-1]["drained"] is True
        event_types = {line["event"]["event_type"] for line in lines if line["kind"] == "event"}
        assert {"PROCESS_DISCOVERED", "CONNECTION_DISCOVERED"} <= event_types

    def test_monitor_persists_and_reads_back(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert (
            cli.main(["monitor", "--json", "--duration", "0.6", "--interval", "0.5"]) == ExitCode.OK
        )
        capsys.readouterr()
        info = run_json(capsys, "db", "info", "--json")
        assert info["counts"]["security_events"] > 0 and info["counts"]["processes"] >= 3
        events = run_json(capsys, "events", "--json", "--type", "PROCESS_DISCOVERED")
        assert events["schema"] == "threatlens.events" and events["count"] > 0
        alerts = run_json(capsys, "alerts", "--json")
        assert alerts["schema"] == "threatlens.alerts"

    def test_read_commands_without_database(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["events", "--json"]) == ExitCode.ERROR  # no DB yet
        assert "No database" in capsys.readouterr().err

    def test_clear_ram_confirmed_and_audited(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from threatlens.response.memory import MemoryTrimmer

        trimmed: list[int] = []
        readings = iter([9_000, 4_000])
        fake = MemoryTrimmer(
            trim=trimmed.append, pids=lambda: [4, 1000, 2000], used_bytes=lambda: next(readings)
        )
        monkeypatch.setattr(cli, "MemoryTrimmer", lambda: fake)
        doc = run_json(capsys, "clear-ram", "--yes", "--json")
        assert doc["schema"] == "threatlens.clear_ram"
        assert doc["action"]["outcome"] == "SUCCEEDED"
        assert doc["action"]["details"]["freed_bytes"] == 5_000
        assert trimmed == [1000, 2000]
        (row,) = [r for r in cli_actions() if r["action_type"] == "TRIM_WORKING_SETS"]
        assert row["outcome"] == "SUCCEEDED"

    def test_clear_ram_without_terminal_or_yes_is_cancelled(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def must_not_run() -> None:
            raise AssertionError("trimmer must not be used when cancelled")

        from threatlens.response.memory import MemoryTrimmer

        monkeypatch.setattr(
            cli, "MemoryTrimmer", lambda: MemoryTrimmer(trim=lambda _: must_not_run())
        )
        assert cli.main(["clear-ram", "--json"]) == ExitCode.CANCELLED

    def test_status_reports_engine_not_running(self, capsys: pytest.CaptureFixture[str]) -> None:
        doc = run_json(capsys, "status", "--json", "--no-self-test")
        assert doc["schema"] == "threatlens.status"
        assert doc["engine_running"] is False and doc["self_test"] == []

    def test_monitor_rejects_unknown_event_category(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(["monitor", "--events", "process,bogus", "--duration", "1"]) == ExitCode.USAGE
        )
        assert "bogus" in capsys.readouterr().err

    def test_rules_list_and_show(self, capsys: pytest.CaptureFixture[str]) -> None:
        listing = run_json(capsys, "rules", "--json")
        ids = [r["rule_id"] for r in listing["rules"]]
        assert len(ids) >= 10 and ids == sorted(ids)
        assert all(r["enabled"] for r in listing["rules"])
        detail = run_json(capsys, "rules", "show", "proc-006", "--json")
        assert detail["rule"]["rule_id"] == "PROC-006" and detail["rule"]["false_positives"]
        assert cli.main(["rules", "show", "NOPE-999"]) == ExitCode.USAGE

    def test_disabled_rule_is_reported_as_disabled(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        cfg = tmp_path / "cfg.toml"
        cfg.write_text('[detection]\ndisabled_rules = ["NET-004"]\n', encoding="utf-8")
        listing = run_json(capsys, "rules", "--json", "--config", str(cfg))
        states = {r["rule_id"]: r["enabled"] for r in listing["rules"]}
        assert states["NET-004"] is False and states["PROC-001"] is True

    def test_inspect_reports_detections_with_evidence(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The fake tool.exe runs from Downloads and connects to a public address on uncommon port
        # 4444; the file does not exist on disk, so its signature is UNKNOWN (not VALID).
        doc = run_json(capsys, "inspect", "2000", "--json", "--sample", "0")
        rule_ids = {d["rule_id"] for d in doc["detections"]}
        assert "NET-004" in rule_ids
        for detection in doc["detections"]:
            assert detection["evidence"] and detection["summary"].startswith("tool.exe")

    def test_monitor_stream_includes_detections(self, capsys: pytest.CaptureFixture[str]) -> None:
        argv = ["monitor", "--json", "--duration", "0.6", "--interval", "0.5"]
        assert cli.main(argv) == ExitCode.OK
        lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        detections = [line["detection"] for line in lines if line["kind"] == "detection"]
        assert any(d["rule_id"] == "NET-004" for d in detections)
        assert lines[-1]["kind"] == "shutdown" and lines[-1]["detections"] == len(detections)

    def test_config_init_then_validate(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        target = tmp_path / "cfg.toml"
        assert cli.main(["config", "init", "--config", str(target), "-q"]) == ExitCode.OK
        assert target.exists()
        doc = run_json(capsys, "config", "validate", "--config", str(target), "--json")
        assert doc["valid"] is True

    def test_invalid_config_exit_code(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("[general]\nrefresh_interval_seconds = 0\n", encoding="utf-8")
        assert cli.main(["processes", "--config", str(bad)]) == ExitCode.USAGE
        assert "refresh_interval_seconds" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv", [["process", "-5"], ["process", "abc"], ["processes", "--sample", "99"], ["bogus"]]
)
def test_invalid_arguments_exit_with_usage(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == ExitCode.USAGE


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == ExitCode.USAGE
    assert "usage: threatlens" in capsys.readouterr().out
