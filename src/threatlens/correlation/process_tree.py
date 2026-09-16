"""Process tree reconstruction.

Windows does not maintain a live parent/child relationship. Each process records only the PID
of its creator at creation time (``InheritedFromUniqueProcessId``). Two consequences:

1. **Orphans.** When the parent exits, the child keeps pointing at a dead PID.
2. **PID reuse.** That dead PID can be handed to a *new, unrelated* process. A naive tree then
   shows e.g. ``chrome.exe`` as the "parent" of a process it never created — a misleading lineage
   that a detection engine could turn into a false alert (or a missed one).

The fix: a candidate parent is accepted only if it was created **no later than** the child. A
process cannot be created by something that did not exist yet.

Limitation: a parent PID can be deliberately spoofed at creation
(``PROC_THREAD_ATTRIBUTE_PARENT_PROCESS``). Polling cannot detect that; ETW/Sysmon record the
real creator and are on the roadmap.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from threatlens.core.models import ProcessInfo, ProcessNode

IDLE_PID: Final = 0
DEFAULT_MAX_DEPTH: Final = 128


def select_parent(child: ProcessInfo, candidates: Iterable[ProcessInfo]) -> ProcessInfo | None:
    """Pick the real parent among process instances holding ``child.ppid``.

    ``candidates`` may include exited instances retained by the engine. A candidate created
    *after* the child cannot be its creator (the PID was reused); among the rest, the most
    recently created instance is the parent.
    """
    if child.ppid is None or child.ppid == child.pid or child.ppid == IDLE_PID:
        return None
    valid = [
        p
        for p in candidates
        if p.pid == child.ppid
        and p.process_key != child.process_key
        and (
            p.create_time is None or child.create_time is None or p.create_time <= child.create_time
        )
    ]
    if not valid:
        return None
    return max(valid, key=lambda p: p.create_time.timestamp() if p.create_time else 0.0)


def verified_parent(child: ProcessInfo, by_pid: Mapping[int, ProcessInfo]) -> ProcessInfo | None:
    """Return the child's real parent among currently running processes, else ``None``."""
    if child.ppid is None:
        return None
    candidate = by_pid.get(child.ppid)
    return select_parent(child, () if candidate is None else (candidate,))


def ancestry(
    process: ProcessInfo, by_pid: Mapping[int, ProcessInfo], limit: int = 32
) -> list[ProcessInfo]:
    """Verified ancestors, nearest first. Stops at the first unverifiable link."""
    chain: list[ProcessInfo] = []
    seen = {process.process_key}
    current = process
    while len(chain) < limit:
        parent = verified_parent(current, by_pid)
        if parent is None or parent.process_key in seen:
            break
        chain.append(parent)
        seen.add(parent.process_key)
        current = parent
    return chain


def children_of(process: ProcessInfo, processes: Iterable[ProcessInfo]) -> list[ProcessInfo]:
    """Direct, verified children of ``process``."""
    candidates = list(processes)
    by_pid = {p.pid: p for p in candidates}
    return [
        p
        for p in candidates
        if (parent := verified_parent(p, by_pid)) is not None
        and parent.process_key == process.process_key
    ]


def build_process_tree(
    processes: Sequence[ProcessInfo], max_depth: int = DEFAULT_MAX_DEPTH
) -> tuple[ProcessNode, ...]:
    """Build a forest of :class:`ProcessNode` roots, sorted by creation time.

    A process whose parent cannot be verified becomes a root with ``parent_verified=False``
    (unless it legitimately has no parent). Depth is capped so a hostile, extremely deep
    process chain cannot exhaust the recursion limit; nodes beyond ``max_depth`` are omitted.
    """
    by_pid = {p.pid: p for p in processes}
    children: dict[str, list[ProcessInfo]] = {}
    roots: list[tuple[ProcessInfo, bool]] = []

    for process in processes:
        parent = verified_parent(process, by_pid)
        if parent is None:
            has_claimed_parent = process.ppid not in (None, IDLE_PID, process.pid)
            roots.append((process, not has_claimed_parent))
        else:
            children.setdefault(parent.process_key, []).append(process)

    def order(p: ProcessInfo) -> tuple[float, int]:
        return (p.create_time.timestamp() if p.create_time else 0.0, p.pid)

    reached: set[str] = set()

    def build(process: ProcessInfo, verified: bool, depth: int) -> ProcessNode:
        reached.add(process.process_key)
        kids: list[ProcessNode] = []
        if depth < max_depth:
            for child in sorted(children.get(process.process_key, []), key=order):
                if child.process_key not in reached:
                    kids.append(build(child, True, depth + 1))
        return ProcessNode(process=process, children=tuple(kids), parent_verified=verified)

    forest = [
        build(process, verified, 0)
        for process, verified in sorted(roots, key=lambda i: order(i[0]))
    ]

    # Processes not reachable from any root (e.g. two processes naming each other as parent with
    # identical creation times) must never silently disappear from a security view.
    for process in sorted(processes, key=order):
        if process.process_key not in reached and not _beyond_depth(process, by_pid, max_depth):
            forest.append(build(process, False, 0))
    return tuple(forest)


def _beyond_depth(process: ProcessInfo, by_pid: Mapping[int, ProcessInfo], max_depth: int) -> bool:
    """True if ``process`` is unreached only because of the depth cap.

    That is the case when its verified ancestry is longer than ``max_depth`` *and* terminates at
    a genuine root; a chain that instead loops back on itself is a cycle and must be surfaced.
    """
    chain = ancestry(process, by_pid, limit=len(by_pid) + 1)
    top = chain[-1] if chain else process
    return len(chain) >= max_depth and verified_parent(top, by_pid) is None


def find_node(roots: Iterable[ProcessNode], pid: int) -> ProcessNode | None:
    """Depth-first search for the node with ``pid``."""
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node.process.pid == pid:
            return node
        stack.extend(node.children)
    return None
