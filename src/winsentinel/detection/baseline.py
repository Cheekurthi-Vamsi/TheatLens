"""Baselines: capture a known-good picture of the host, then report what changed since.

A baseline is a set of :class:`BaselineItem` rows describing what existed at capture time:
running executables, listening ports, persistence entries and auto-start services. Comparing the
current host against a baseline surfaces exactly the additions — a new executable, a new
listener, a new autostart — which is one of the strongest ways to notice that *something changed*
after a known-good moment (spec §18, §49).

Baselines carry an expiry and a capture host, so a stale baseline (or one from another machine)
is flagged rather than trusted forever. Capture and comparison here are pure functions over
snapshots; persistence and the CLI live elsewhere.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from winsentinel.core.models import (
    CorrelatedConnection,
    PersistenceSnapshot,
    ProcessInfo,
)
from winsentinel.detection.paths import normalize


class BaselineItemKind(StrEnum):
    PROCESS = "PROCESS"
    LISTENER = "LISTENER"
    PERSISTENCE = "PERSISTENCE"
    SERVICE = "SERVICE"


@dataclass(frozen=True, slots=True)
class BaselineItem:
    kind: BaselineItemKind
    item_key: str
    label: str
    attributes: dict[str, Any]


@dataclass(frozen=True, slots=True)
class BaselineDiff:
    kind: BaselineItemKind
    label: str
    attributes: dict[str, Any]


def capture_processes(processes: Sequence[ProcessInfo]) -> list[BaselineItem]:
    """One item per distinct executable path (not per PID — many PIDs share an exe)."""
    seen: dict[str, BaselineItem] = {}
    for process in processes:
        if process.exe is None:
            continue
        key = normalize(process.exe)
        if key not in seen:
            seen[key] = BaselineItem(
                BaselineItemKind.PROCESS,
                key,
                process.exe,
                {"name": process.name, "exe": process.exe},
            )
    return list(seen.values())


def capture_listeners(connections: Sequence[CorrelatedConnection]) -> list[BaselineItem]:
    seen: dict[str, BaselineItem] = {}
    for item in connections:
        conn = item.connection
        if not conn.is_listener or conn.local_scope.value == "LOOPBACK":
            continue
        key = f"{conn.protocol.value}/{conn.local_port}"
        if key not in seen:
            seen[key] = BaselineItem(
                BaselineItemKind.LISTENER,
                key,
                f"{conn.protocol.value} :{conn.local_port} ({item.process_name or '?'})",
                {
                    "protocol": conn.protocol.value,
                    "port": conn.local_port,
                    "process": item.process_name,
                },
            )
    return list(seen.values())


def capture_persistence(snapshot: PersistenceSnapshot) -> list[BaselineItem]:
    items: list[BaselineItem] = []
    for entry in snapshot.items:
        kind = (
            BaselineItemKind.SERVICE
            if entry.kind.value == "SERVICE"
            else BaselineItemKind.PERSISTENCE
        )
        items.append(
            BaselineItem(
                kind,
                entry.item_key,
                f"{entry.kind.value}: {entry.name}",
                {"kind": entry.kind.value, "name": entry.name, "executable": entry.executable},
            )
        )
    return items


def capture_baseline(
    processes: Sequence[ProcessInfo],
    connections: Sequence[CorrelatedConnection],
    persistence: PersistenceSnapshot,
) -> list[BaselineItem]:
    return [
        *capture_processes(processes),
        *capture_listeners(connections),
        *capture_persistence(persistence),
    ]


def compare_baseline(
    baseline: Sequence[BaselineItem], current: Sequence[BaselineItem]
) -> list[BaselineDiff]:
    """Return the items present now but absent from the baseline (new since capture)."""
    known = {(item.kind, item.item_key) for item in baseline}
    return [
        BaselineDiff(item.kind, item.label, item.attributes)
        for item in current
        if (item.kind, item.item_key) not in known
    ]


def diffs_by_kind(diffs: Sequence[BaselineDiff]) -> dict[BaselineItemKind, list[BaselineDiff]]:
    grouped: dict[BaselineItemKind, list[BaselineDiff]] = {}
    for diff in diffs:
        grouped.setdefault(diff.kind, []).append(diff)
    return grouped
