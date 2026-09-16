from __future__ import annotations

from datetime import timedelta

from fixtures.fakes import BASE_TIME, minutes, process
from threatlens.core.models import EventType, ProcessSnapshot
from threatlens.monitors.process_monitor import diff_snapshots


def snap(*processes: object, at: float = 5) -> ProcessSnapshot:
    return ProcessSnapshot(timestamp=BASE_TIME + timedelta(minutes=at), processes=tuple(processes))  # type: ignore[arg-type]


def test_first_snapshot_is_inventory_not_starts() -> None:
    assert diff_snapshots(None, snap(process(100))) == []


def test_unchanged_snapshot_yields_nothing() -> None:
    p = process(100)
    assert diff_snapshots(snap(p), snap(p, at=6)) == []


def test_started_and_stopped() -> None:
    old = process(100, name="old.exe")
    new = process(200, name="new.exe", created=minutes(5.5))
    events = diff_snapshots(snap(old), snap(new, at=6))
    assert [e.event_type for e in events] == [EventType.PROCESS_STARTED, EventType.PROCESS_STOPPED]
    started, stopped = events
    assert started.pid == 200 and started.data["name"] == "new.exe"
    assert started.process_key == new.process_key
    assert stopped.pid == 100
    assert stopped.data["exited_after"] == (BASE_TIME + timedelta(minutes=5)).isoformat()
    assert stopped.data["exited_before"] == (BASE_TIME + timedelta(minutes=6)).isoformat()


def test_pid_reuse_between_polls_is_stop_plus_start() -> None:
    before = process(100, name="first.exe", created=minutes(0))
    after = process(100, name="second.exe", created=minutes(5.5))
    events = diff_snapshots(snap(before), snap(after, at=6))
    assert sorted(e.event_type for e in events) == [
        EventType.PROCESS_STARTED,
        EventType.PROCESS_STOPPED,
    ]


def test_started_events_ordered_parents_first_with_verified_parent_key() -> None:
    parent = process(300, ppid=4, name="parent.exe", created=minutes(5.1))
    child = process(301, ppid=300, name="child.exe", created=minutes(5.2))
    events = diff_snapshots(snap(), snap(child, parent, at=6))
    assert [e.pid for e in events] == [300, 301]
    assert events[1].data["parent_key"] == parent.process_key
    assert events[1].data["parent_name"] == "parent.exe"


def test_parent_key_absent_when_ppid_was_reused() -> None:
    child = process(301, ppid=300, created=minutes(5.2))
    impostor = process(300, name="impostor.exe", created=minutes(5.3))  # newer than child
    events = diff_snapshots(snap(impostor), snap(impostor, child, at=6))
    (started,) = events
    assert started.data["ppid"] == 300
    assert started.data["parent_key"] is None


def test_suspended_toggle_emits_changed() -> None:
    running = process(100, suspended=False)
    frozen = process(100, suspended=True)
    (event,) = diff_snapshots(snap(running), snap(frozen, at=6))
    assert event.event_type is EventType.PROCESS_CHANGED
    assert event.data["changed"] == {"suspended": [False, True]}


def test_unknown_suspended_state_is_not_a_change() -> None:
    assert (
        diff_snapshots(snap(process(100, suspended=None)), snap(process(100, suspended=True), at=6))
        == []
    )
