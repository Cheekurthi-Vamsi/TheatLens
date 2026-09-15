from __future__ import annotations

from datetime import timedelta

from fixtures.fakes import connection, minutes, process
from winsentinel.core.models import Attribution
from winsentinel.correlation.process_network import (
    attribute,
    connection_chain,
    correlate,
    group_by_process,
    lookup_from_processes,
)


def test_socket_attributed_to_its_process() -> None:
    owner = process(500, created=minutes(0))
    attribution, found = attribute(connection(500, created=minutes(1)), [owner])
    assert attribution is Attribution.ATTRIBUTED and found is owner


def test_pid_reuse_is_detected_not_misattributed() -> None:
    """Socket created at minute 1; the only process now holding PID 500 started at minute 3."""
    newcomer = process(500, name="innocent.exe", created=minutes(3))
    attribution, found = attribute(connection(500, created=minutes(1)), [newcomer])
    assert attribution is Attribution.PID_REUSE_SUSPECTED
    assert found is None


def test_picks_the_right_instance_among_several_with_same_pid() -> None:
    old = process(500, name="old.exe", created=minutes(0))  # exited, retained
    new = process(500, name="new.exe", created=minutes(2))
    _, owner_of_old_socket = attribute(connection(500, created=minutes(1)), [old, new])
    _, owner_of_new_socket = attribute(connection(500, created=minutes(3)), [old, new])
    assert owner_of_old_socket is old
    assert owner_of_new_socket is new


def test_tolerance_absorbs_millisecond_rounding() -> None:
    owner = process(500, created=minutes(1))
    socket_ = connection(500, created=minutes(1) - timedelta(milliseconds=400))
    assert attribute(socket_, [owner])[0] is Attribution.ATTRIBUTED


def test_idle_system_and_unknown_pids() -> None:
    system = process(4, ppid=None, name="System", created=None)
    assert attribute(connection(0), [])[0] is Attribution.UNATTRIBUTED
    assert attribute(connection(4), [system]) == (Attribution.KERNEL, system)
    assert attribute(connection(777), [])[0] is Attribution.UNATTRIBUTED


def test_correlate_and_group() -> None:
    chrome = process(100, name="chrome.exe", created=minutes(0))
    tool = process(200, name="tool.exe", created=minutes(0))
    items = correlate(
        [
            connection(100, local_port=1),
            connection(100, local_port=2),
            connection(200, local_port=3),
            connection(999, local_port=4),
        ],
        lookup_from_processes([chrome, tool]),
    )
    groups = group_by_process(items, {p.process_key: p for p in (chrome, tool)})
    assert [(g.process.name if g.process else None, len(g.connections)) for g in groups] == [
        ("chrome.exe", 2),
        ("tool.exe", 1),
        (None, 1),
    ]
    assert groups[2].attribution is Attribution.UNATTRIBUTED


def test_connection_chain_includes_verified_ancestry() -> None:
    explorer = process(10, ppid=None, name="explorer.exe", created=minutes(0))
    shell = process(20, ppid=10, name="powershell.exe", created=minutes(1))
    tool = process(30, ppid=20, name="tool.exe", created=minutes(2))
    processes = [explorer, shell, tool]
    (item,) = correlate([connection(30, created=minutes(3))], lookup_from_processes(processes))
    chain = connection_chain(item, processes)
    assert chain.process is tool
    assert [p.name for p in chain.ancestors] == ["powershell.exe", "explorer.exe"]
