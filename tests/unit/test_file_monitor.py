from __future__ import annotations

from fixtures.detection import host, settings
from winsentinel.core.models import EventType, SecurityEvent
from winsentinel.detection.rules.file import ExecutableDroppedInSensitiveLocation
from winsentinel.monitors.file_monitor import FileMonitor, is_executable_or_script


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def make_monitor() -> tuple[FileMonitor, list[SecurityEvent], Clock]:
    published: list[SecurityEvent] = []
    monitor = FileMonitor(published.append, paths=[])
    clock = Clock()
    monitor._monotonic = clock
    return monitor, published, clock


def test_emit_builds_event_with_metadata() -> None:
    monitor, published, _ = make_monitor()
    monitor.emit(EventType.FILE_CREATED, r"C:\Users\a\AppData\Local\Temp\dropper.exe")
    (event,) = published
    assert event.event_type is EventType.FILE_CREATED
    assert event.data["name"] == "dropper.exe"
    assert event.data["extension"] == ".exe"
    assert event.data["executable_or_script"] is True


def test_modified_events_are_debounced() -> None:
    monitor, published, clock = make_monitor()
    monitor.emit(EventType.FILE_MODIFIED, r"C:\Temp\a.txt", debounce=True)
    monitor.emit(EventType.FILE_MODIFIED, r"C:\Temp\a.txt", debounce=True)  # within window: dropped
    assert len(published) == 1
    clock.now += 5
    monitor.emit(EventType.FILE_MODIFIED, r"C:\Temp\a.txt", debounce=True)  # after window: emitted
    assert len(published) == 2


def test_created_events_are_never_debounced() -> None:
    monitor, published, _ = make_monitor()
    monitor.emit(EventType.FILE_CREATED, r"C:\Temp\a.exe")
    monitor.emit(EventType.FILE_CREATED, r"C:\Temp\a.exe")
    assert len(published) == 2


def test_is_executable_or_script() -> None:
    assert is_executable_or_script("x.EXE") and is_executable_or_script("run.ps1")
    assert not is_executable_or_script("photo.jpg") and not is_executable_or_script("readme")


def file_event(path: str, event_type: EventType = EventType.FILE_CREATED) -> SecurityEvent:
    from winsentinel.monitors.file_monitor import _extension, is_executable_or_script

    return SecurityEvent(
        event_type=event_type,
        source="test",
        data={
            "path": path,
            "name": path.rsplit("\\", 1)[-1],
            "extension": _extension(path),
            "executable_or_script": is_executable_or_script(path),
        },
    )


class TestFileRule:
    def test_executable_in_temp_is_low(self) -> None:
        event = file_event(r"C:\Users\a\AppData\Local\Temp\payload.exe")
        result = ExecutableDroppedInSensitiveLocation(settings()).evaluate(event, host([]))
        assert result is not None and result.rule_id == "FILE-001" and result.score == 20

    def test_executable_in_startup_is_medium(self) -> None:
        path = r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe"
        result = ExecutableDroppedInSensitiveLocation(settings()).evaluate(
            file_event(path), host([])
        )
        assert result is not None and result.score == 30
        assert any("logon" in e.description for e in result.evidence)

    def test_non_executable_is_ignored(self) -> None:
        event = file_event(r"C:\Users\a\Downloads\notes.txt")
        assert ExecutableDroppedInSensitiveLocation(settings()).evaluate(event, host([])) is None
