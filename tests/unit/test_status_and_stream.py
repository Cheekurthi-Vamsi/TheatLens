from __future__ import annotations

import io
import json
from datetime import timedelta
from pathlib import Path

import pytest
from rich.console import Console

from fixtures.fakes import BASE_TIME, minutes
from threatlens.core.models import (
    BusStats,
    EngineState,
    EngineStats,
    EngineStatus,
    EventType,
    SecurityEvent,
)
from threatlens.core.status_file import (
    EngineAlreadyRunningError,
    InstanceLock,
    StatusFile,
    is_status_current,
)
from threatlens.ui.event_stream import EventStreamPrinter, format_event


def status(state: EngineState = EngineState.RUNNING, updated: float = 5) -> EngineStatus:
    return EngineStatus(
        version="0.1.0",
        pid=1234,
        process_key="1234:1",
        state=state,
        started_at=BASE_TIME,
        updated_at=minutes(updated),
        interval_seconds=2.0,
        components=(),
        bus=BusStats(capacity=10, queued=0, published=0, dispatched=0, dropped=0, handler_errors=0),
        stats=EngineStats(),
    )


class TestStatusFile:
    def test_round_trip_and_atomic_write(self, tmp_path: Path) -> None:
        target = StatusFile(tmp_path / "sub" / "engine-status.json")
        target.write(status())
        assert target.read() == status()
        assert [p.name for p in target.path.parent.iterdir()] == ["engine-status.json"]

    @pytest.mark.parametrize("content", [b"{not json", b'{"schema_version": 1}', b"\x00\xff"])
    def test_untrusted_content_is_rejected(self, tmp_path: Path, content: bytes) -> None:
        path = tmp_path / "engine-status.json"
        path.write_bytes(content)
        assert StatusFile(path).read() is None

    def test_missing_file(self, tmp_path: Path) -> None:
        assert StatusFile(tmp_path / "none.json").read() is None

    def test_currency_rules(self) -> None:
        now = minutes(5) + timedelta(seconds=3)
        fresh = timedelta(seconds=10)
        assert is_status_current(status(), now, stale_after=fresh, process_alive=True)
        assert not is_status_current(status(), now, stale_after=fresh, process_alive=False)
        assert not is_status_current(
            status(EngineState.STOPPED), now, stale_after=fresh, process_alive=True
        )
        assert not is_status_current(status(updated=4), now, stale_after=fresh, process_alive=True)

    def test_instance_lock_is_exclusive_and_released(self, tmp_path: Path) -> None:
        path = tmp_path / "engine.lock"
        with InstanceLock(path), pytest.raises(EngineAlreadyRunningError):
            InstanceLock(path).__enter__()
        with InstanceLock(path):
            pass


def stream_event(event_type: EventType, **data: object) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type, source="test", pid=4832, timestamp=BASE_TIME, data=data
    )


class TestEventStream:
    def test_format_connection(self) -> None:
        line = format_event(
            stream_event(
                EventType.CONNECTION_OPENED,
                process="unknown.exe",
                protocol="TCP",
                local_address="10.0.0.5",
                local_port=52144,
                remote_address="185.1.2.3",
                remote_port=4444,
                state="ESTABLISHED",
                direction="OUTBOUND",
                remote_scope="PUBLIC",
                attribution="ATTRIBUTED",
            )
        ).plain
        assert "CONNECTION_OPENED" in line and "unknown.exe (4832)" in line
        assert "10.0.0.5:52144 → 185.1.2.3:4444" in line and "PUBLIC" in line

    def test_format_process_and_health(self) -> None:
        started = format_event(
            stream_event(
                EventType.PROCESS_STARTED, name="evil\x1b]0;x\x07.exe", parent_name="winword.exe"
            )
        ).plain
        assert "\x1b" not in started and "\\x1b" in started and "← winword.exe" in started
        health = format_event(
            SecurityEvent(
                event_type=EventType.COLLECTOR_STATUS,
                source="engine",
                timestamp=BASE_TIME,
                data={
                    "component": "network_monitor",
                    "status": "UNAVAILABLE",
                    "previous_status": "DEGRADED",
                    "last_error": "boom",
                },
            )
        ).plain
        assert "network_monitor: DEGRADED → UNAVAILABLE" in health and "boom" in health

    def test_filters_and_json_lines(self) -> None:
        buffer = io.StringIO()
        printer = EventStreamPrinter(
            Console(file=io.StringIO()), categories={"network"}, json_lines=True, stream=buffer
        )
        printer.on_event(
            stream_event(EventType.PROCESS_STARTED, name="a.exe")
        )  # filtered by category
        printer.on_event(
            stream_event(EventType.CONNECTION_OPENED, remote_scope="LOOPBACK")
        )  # loopback hidden
        printer.on_event(
            stream_event(EventType.CONNECTION_OPENED, remote_scope="PUBLIC", process="b.exe")
        )
        (line,) = buffer.getvalue().splitlines()
        payload = json.loads(line)
        assert payload["kind"] == "event" and payload["event"]["data"]["process"] == "b.exe"
