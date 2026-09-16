from __future__ import annotations

from datetime import timedelta

from fixtures.fakes import BASE_TIME, connection, minutes, process
from threatlens.core.models import (
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    Direction,
    EventType,
    ProcessSnapshot,
    SecurityEvent,
    SignatureInfo,
    SignatureStatus,
    TransportProtocol,
)
from threatlens.core.state import SystemState
from threatlens.monitors.network_monitor import diff_connections, inventory_events
from threatlens.monitors.process_monitor import inventory_events as process_inventory


def snap(*processes: object, at: float) -> ProcessSnapshot:
    return ProcessSnapshot(timestamp=minutes(at), processes=tuple(processes))  # type: ignore[arg-type]


def correlated(
    conn: object, name: str = "app.exe", key: str | None = "100:0"
) -> CorrelatedConnection:
    return CorrelatedConnection(
        connection=conn,  # type: ignore[arg-type]
        attribution=Attribution.ATTRIBUTED,
        process_key=key,
        process_name=name,
    )


class TestSystemState:
    def test_exited_parent_remains_resolvable_within_retention(self) -> None:
        clock = {"now": minutes(10)}
        state = SystemState(exit_retention=timedelta(minutes=5), clock=lambda: clock["now"])
        cmd = process(200, ppid=4, name="cmd.exe", created=minutes(9))
        payload = process(300, ppid=200, name="payload.exe", created=minutes(9.5))
        state.apply_process_snapshot(snap(cmd, payload, at=9.6))
        state.apply_process_snapshot(snap(payload, at=10))  # cmd.exe exited
        assert not state.is_running(cmd.process_key)
        assert state.parent_of(payload) == cmd
        assert [p.name for p in state.ancestors(payload)] == ["cmd.exe"]

        state.apply_process_snapshot(snap(payload, at=16))  # beyond retention
        assert state.process(cmd.process_key) is None
        assert state.parent_of(payload) is None

    def test_parent_lookup_rejects_newer_process_with_reused_pid(self) -> None:
        state = SystemState()
        child = process(300, ppid=200, created=minutes(1))
        impostor = process(200, name="impostor.exe", created=minutes(2))
        state.apply_process_snapshot(snap(child, impostor, at=3))
        assert state.parent_of(child) is None

    def test_enrichment_survives_new_snapshots(self) -> None:
        state = SystemState()
        tool = process(100, created=minutes(0))
        state.apply_process_snapshot(snap(tool, at=1))
        signature = SignatureInfo(status=SignatureStatus.UNSIGNED)
        state.set_enrichment(tool.process_key, "cd" * 32, signature)
        state.apply_process_snapshot(snap(process(100, created=minutes(0)), at=2))
        merged = state.process_by_pid(100)
        assert merged is not None and merged.sha256 == "cd" * 32
        assert merged.signature == signature

    def test_observe_process_replaces_instance_with_reused_pid(self) -> None:
        state = SystemState(clock=lambda: minutes(5))
        old = process(100, name="old.exe", created=minutes(0))
        state.apply_process_snapshot(snap(old, at=1))
        new = process(100, name="new.exe", created=minutes(4))
        state.observe_process(new)
        assert state.process_by_pid(100) == new
        assert {p.name for p in state.candidates_for_pid(100)} == {"old.exe", "new.exe"}

    def test_event_history_window(self) -> None:
        clock = {"now": minutes(10)}
        state = SystemState(clock=lambda: clock["now"])
        for at in (1, 9.9):
            state.record_event(
                SecurityEvent(
                    event_type=EventType.CONNECTION_OPENED,
                    source="t",
                    process_key="k",
                    timestamp=minutes(at),
                )
            )
        assert len(state.events_for("k")) == 2
        assert len(state.events_for("k", within=timedelta(minutes=1))) == 1


class TestNetworkMonitor:
    def test_inventory_events_split_listeners_and_connections(self) -> None:
        listener = correlated(
            connection(
                100,
                remote=None,
                remote_port=None,
                local="0.0.0.0",
                local_port=8080,
                state=ConnectionState.LISTEN,
                direction=Direction.LISTENING,
            )
        )
        outbound = correlated(connection(100))
        types = [e.event_type for e in inventory_events([listener, outbound], BASE_TIME)]
        assert types == [EventType.LISTENER_DISCOVERED, EventType.CONNECTION_DISCOVERED]

    def test_opened_and_closed(self) -> None:
        old = correlated(connection(100, local_port=50000))
        new = correlated(connection(100, local_port=50001))
        events = diff_connections({old.connection.connection_key: old}, [new], BASE_TIME)
        assert [(e.event_type, e.data["local_port"]) for e in events] == [
            (EventType.CONNECTION_OPENED, 50001),
            (EventType.CONNECTION_CLOSED, 50000),
        ]
        assert events[0].process_key == "100:0"

    def test_state_change_on_same_socket_is_not_a_new_connection(self) -> None:
        syn = correlated(connection(100, state=ConnectionState.SYN_SENT))
        established = correlated(connection(100, state=ConnectionState.ESTABLISHED))
        assert (
            diff_connections({syn.connection.connection_key: syn}, [established], BASE_TIME) == []
        )

    def test_noise_filters(self) -> None:
        lingering = correlated(connection(0, state=ConnectionState.TIME_WAIT), key=None)
        ephemeral_udp = correlated(
            connection(
                100,
                remote=None,
                remote_port=None,
                local_port=61000,
                protocol=TransportProtocol.UDP,
                state=ConnectionState.NONE,
                direction=Direction.BOUND,
            )
        )
        fixed_udp = correlated(
            connection(
                100,
                remote=None,
                remote_port=None,
                local_port=5353,
                protocol=TransportProtocol.UDP,
                state=ConnectionState.NONE,
                direction=Direction.BOUND,
            )
        )
        events = diff_connections({}, [lingering, ephemeral_udp, fixed_udp], BASE_TIME)
        assert [(e.event_type, e.data["local_port"]) for e in events] == [
            (EventType.LISTENER_OPENED, 5353)
        ]


def test_process_inventory_events_are_discovered_parents_first() -> None:
    parent = process(10, ppid=None, name="explorer.exe", created=minutes(0))
    child = process(20, ppid=10, name="app.exe", created=minutes(1))
    events = process_inventory(snap(child, parent, at=2))
    assert [(e.event_type, e.pid) for e in events] == [
        (EventType.PROCESS_DISCOVERED, 10),
        (EventType.PROCESS_DISCOVERED, 20),
    ]
    assert events[1].data["parent_name"] == "explorer.exe"
