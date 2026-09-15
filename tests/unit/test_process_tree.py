from __future__ import annotations

from fixtures.fakes import minutes, process
from winsentinel.core.models import ProcessNode
from winsentinel.correlation.process_tree import (
    ancestry,
    build_process_tree,
    children_of,
    find_node,
    verified_parent,
)


def all_pids(roots: tuple[ProcessNode, ...]) -> list[int]:
    out: list[int] = []
    stack = list(roots)
    while stack:
        node = stack.pop()
        out.append(node.process.pid)
        stack.extend(node.children)
    return sorted(out)


def sample() -> list:  # type: ignore[type-arg]
    return [
        process(4, ppid=None, name="System", created=None),
        process(500, ppid=4, name="smss.exe", created=minutes(0)),
        process(1000, ppid=900, name="explorer.exe", created=minutes(1)),  # parent exited
        process(1100, ppid=1000, name="powershell.exe", created=minutes(2)),
        process(1200, ppid=1100, name="python.exe", created=minutes(3)),
    ]


def test_every_process_appears_exactly_once() -> None:
    processes = sample()
    roots = build_process_tree(processes)
    assert all_pids(roots) == sorted(p.pid for p in processes)


def test_lineage_and_orphan_marking() -> None:
    roots = build_process_tree(sample())
    by_name = {r.process.name: r for r in roots}
    assert set(by_name) == {"System", "explorer.exe"}
    assert by_name["System"].parent_verified is True  # genuinely parentless
    assert by_name["explorer.exe"].parent_verified is False  # claimed parent 900 is gone
    powershell = by_name["explorer.exe"].children[0]
    assert powershell.process.name == "powershell.exe"
    assert powershell.children[0].process.name == "python.exe"


def test_reused_parent_pid_is_rejected() -> None:
    child = process(200, ppid=100, created=minutes(1))
    impostor = process(100, name="impostor.exe", created=minutes(2))  # created AFTER the child
    assert verified_parent(child, {100: impostor, 200: child}) is None
    roots = build_process_tree([impostor, child])
    assert {r.process.pid for r in roots} == {100, 200}
    assert next(r for r in roots if r.process.pid == 200).parent_verified is False


def test_parent_created_at_same_instant_is_accepted() -> None:
    parent = process(100, created=minutes(1))
    child = process(200, ppid=100, created=minutes(1))
    assert verified_parent(child, {100: parent}) is parent


def test_idle_process_is_never_a_parent() -> None:
    idle = process(0, ppid=None, name="System Idle Process", created=None)
    odd = process(8, ppid=0, created=minutes(1))
    assert verified_parent(odd, {0: idle}) is None


def test_mutual_parent_cycle_never_hides_processes() -> None:
    a = process(100, ppid=200, created=minutes(1))
    b = process(200, ppid=100, created=minutes(1))
    roots = build_process_tree([a, b])
    assert all_pids(roots) == [100, 200]
    assert roots[0].parent_verified is False


def test_depth_cap_limits_recursion() -> None:
    chain = [process(10, ppid=None, created=minutes(0))]
    for i in range(1, 50):
        chain.append(process(10 + i, ppid=10 + i - 1, created=minutes(i)))
    (root,) = build_process_tree(chain, max_depth=5)
    depth = 0
    node = root
    while node.children:
        node = node.children[0]
        depth += 1
    assert depth == 5


def test_ancestry_nearest_first() -> None:
    processes = sample()
    by_pid = {p.pid: p for p in processes}
    names = [p.name for p in ancestry(by_pid[1200], by_pid)]
    assert names == ["powershell.exe", "explorer.exe"]


def test_children_of_and_find_node() -> None:
    processes = sample()
    by_pid = {p.pid: p for p in processes}
    assert [c.pid for c in children_of(by_pid[1000], processes)] == [1100]
    node = find_node(build_process_tree(processes), 1100)
    assert node is not None and node.children[0].process.pid == 1200
    assert find_node(build_process_tree(processes), 424242) is None
