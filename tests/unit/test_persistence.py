from __future__ import annotations

from datetime import UTC, datetime

from fixtures.detection import host, settings
from threatlens.core.models import EventType, SecurityEvent
from threatlens.core.models.persistence import (
    PersistenceItem,
    PersistenceKind,
    PersistenceSnapshot,
)
from threatlens.detection.rules.persistence import NewAutorunEntry, NewScheduledTaskOrService
from threatlens.monitors.persistence_monitor import diff_persistence

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def item(
    name: str, exe: str, kind: PersistenceKind = PersistenceKind.REGISTRY_RUN
) -> PersistenceItem:
    return PersistenceItem(
        kind=kind,
        location=r"HKCU\...\Run" if kind is PersistenceKind.REGISTRY_RUN else "Task Scheduler",
        name=name,
        command=f'"{exe}" --run',
        executable=exe,
    )


def snap(*items: PersistenceItem, at: datetime = NOW) -> PersistenceSnapshot:
    return PersistenceSnapshot(timestamp=at, items=tuple(items))


class TestDiff:
    def test_first_snapshot_is_inventory(self) -> None:
        events = diff_persistence(None, snap(item("A", r"C:\a.exe")))
        assert [e.event_type for e in events] == [EventType.PERSISTENCE_DISCOVERED]

    def test_added_removed_changed(self) -> None:
        before = snap(item("Keep", r"C:\keep.exe"), item("Gone", r"C:\gone.exe"))
        after = snap(
            item("Keep", r"C:\keep.exe"),
            item("New", r"C:\new.exe"),
        )
        events = diff_persistence(before, after)
        types = {(e.event_type, e.data["name"]) for e in events}
        assert (EventType.PERSISTENCE_ADDED, "New") in types
        assert (EventType.PERSISTENCE_REMOVED, "Gone") in types

    def test_command_change_is_changed_event(self) -> None:
        before = snap(item("A", r"C:\a.exe"))
        modified = PersistenceItem(
            kind=PersistenceKind.REGISTRY_RUN,
            location=r"HKCU\...\Run",
            name="A",
            command="evil.exe",
            executable="evil.exe",
        )
        (event,) = diff_persistence(before, snap(modified))
        assert event.event_type is EventType.PERSISTENCE_CHANGED
        assert event.data["previous_command"] == '"C:\\a.exe" --run'


def added_event(**data: object) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.PERSISTENCE_ADDED, source="test", timestamp=NOW, data=data
    )


class TestPersistRules:
    def test_persist_001_fires_for_new_run_key(self) -> None:
        event = added_event(
            kind="REGISTRY_RUN",
            location=r"HKCU\...\Run",
            name="Backdoor",
            command=r'"C:\Users\a\AppData\Local\Temp\x.exe"',
            executable=r"C:\Users\a\AppData\Local\Temp\x.exe",
            item_key="registry_run|hkcu|backdoor",
        )
        result = NewAutorunEntry(settings()).evaluate(event, host([]))
        assert result is not None and result.rule_id == "PERSIST-001"
        assert result.score == 30  # temp location escalates
        assert any("Temp" in e.description for e in result.evidence)

    def test_persist_001_low_for_trusted_location(self) -> None:
        event = added_event(
            kind="REGISTRY_RUN",
            location=r"HKLM\...\Run",
            name="Updater",
            command=r"C:\Program Files\App\updater.exe",
            executable=r"C:\Program Files\App\updater.exe",
            item_key="k",
        )
        result = NewAutorunEntry(settings()).evaluate(event, host([]))
        assert result is not None and result.score == 20

    def test_persist_002_service_and_task(self) -> None:
        for kind in ("SERVICE", "SCHEDULED_TASK"):
            event = added_event(
                kind=kind,
                location="service:evil" if kind == "SERVICE" else "Task Scheduler",
                name="evil",
                executable=r"C:\Users\a\AppData\Local\Temp\svc.exe",
                item_key=f"{kind}|x",
            )
            result = NewScheduledTaskOrService(settings()).evaluate(event, host([]))
            assert result is not None and result.rule_id == "PERSIST-002" and result.score == 35

    def test_rules_ignore_other_kinds(self) -> None:
        run_event = added_event(kind="REGISTRY_RUN", name="x", item_key="k")
        assert NewScheduledTaskOrService(settings()).evaluate(run_event, host([])) is None
        svc_event = added_event(kind="SERVICE", name="x", item_key="k")
        assert NewAutorunEntry(settings()).evaluate(svc_event, host([])) is None
