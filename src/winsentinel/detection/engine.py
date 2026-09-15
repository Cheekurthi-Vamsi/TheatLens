"""Detection engine: routes events to rules, isolates failures, de-duplicates results.

* **Routing.** Each rule declares the event types it cares about; only those reach it.
* **Isolation.** A rule that raises is logged and counted; after ``max_consecutive_failures`` in
  a row it is disabled for the rest of the run (visible in stats) instead of spamming errors on
  every event. Other rules are unaffected.
* **De-duplication.** A rule reports the same finding for the same process instance once
  (``rule_id`` + ``process_key`` + the rule's ``dedup_key``). Memory is bounded.
* **Ignored executables** (``detection.ignored_executables``) suppress results by full path.
* **No actions.** Results go to listeners (stream, later scoring/storage). Nothing here can
  suspend, kill or block anything.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import Final

from winsentinel.core.interfaces import DetectionRule, StateView
from winsentinel.core.models import (
    DetectionResult,
    EventType,
    ProcessInfo,
    RuleMetadata,
    SecurityEvent,
)
from winsentinel.correlation.process_tree import ancestry
from winsentinel.detection.allowlist import AllowlistMatcher
from winsentinel.detection.paths import normalize
from winsentinel.utils.lru import BoundedLRUCache

logger = logging.getLogger(__name__)

# Return values are ignored, so a listener that also returns (e.g. AlertManager.handle) fits.
DetectionListener = Callable[[DetectionResult], object]
DEFAULT_MAX_CONSECUTIVE_FAILURES: Final = 10


@dataclass(frozen=True, slots=True)
class DetectionStats:
    rules_enabled: int
    evaluations: int
    detections: int
    duplicates_suppressed: int
    ignored: int
    rule_errors: dict[str, int]
    auto_disabled: tuple[str, ...]


class DetectionEngine:
    name: Final = "detection"

    def __init__(
        self,
        rules: Sequence[DetectionRule],
        state: StateView,
        *,
        disabled_rules: Collection[str] = (),
        ignored_executables: Collection[str] = (),
        dedup_capacity: int = 20_000,
        recent_capacity: int = 500,
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
    ) -> None:
        ids = [rule.meta.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule IDs")
        disabled = set(disabled_rules)
        self._rules = [
            r for r in rules if r.meta.rule_id not in disabled and r.meta.enabled_by_default
        ]
        self._state = state
        self._ignored = frozenset(normalize(path) for path in ignored_executables)
        self._max_failures = max_consecutive_failures
        self._by_type: dict[EventType, list[DetectionRule]] = {}
        for rule in self._rules:
            for event_type in rule.meta.event_types:
                self._by_type.setdefault(event_type, []).append(rule)
        self._listeners: list[DetectionListener] = []
        self._excluded_keys: frozenset[str] = frozenset()
        self._allowlist: AllowlistMatcher | None = None
        self._allowlisted = 0
        self._seen: BoundedLRUCache[tuple[str, str, str], bool] = BoundedLRUCache(dedup_capacity)
        self._recent: deque[DetectionResult] = deque(maxlen=recent_capacity)
        self._lock = threading.Lock()
        self._consecutive_failures: dict[str, int] = {}
        self._rule_errors: dict[str, int] = {}
        self._auto_disabled: set[str] = set()
        self._evaluations = 0
        self._detections = 0
        self._duplicates = 0
        self._ignored_count = 0

    @property
    def event_types(self) -> frozenset[EventType]:
        return frozenset(self._by_type)

    @property
    def enabled_rules(self) -> list[RuleMetadata]:
        return [rule.meta for rule in self._rules]

    def subscribe(self, listener: DetectionListener) -> None:
        self._listeners.append(listener)

    def set_allowlist(self, allowlist: AllowlistMatcher | None) -> None:
        with self._lock:
            self._allowlist = allowlist

    def exclude_process_keys(self, process_keys: Collection[str]) -> None:
        """Never report these exact process *instances* (used for WinSentinel's own processes).

        Exclusion is by process key (PID + creation time), not by name or path: a copy of
        winsentinel.exe elsewhere, or a later instance with a reused PID, is still evaluated.
        """
        with self._lock:
            self._excluded_keys = frozenset(process_keys)

    def handle(self, event: SecurityEvent) -> list[DetectionResult]:
        """Evaluate every applicable rule. Never raises for rule failures."""
        results: list[DetectionResult] = []
        for rule in self._by_type.get(event.event_type, ()):
            rule_id = rule.meta.rule_id
            if rule_id in self._auto_disabled:
                continue
            try:
                result = rule.evaluate(event, self._state)
            except Exception as exc:
                self._record_failure(rule_id, event, exc)
                continue
            with self._lock:
                self._evaluations += 1
                self._consecutive_failures[rule_id] = 0
            if result is None:
                continue
            if result.process_key is not None and result.process_key in self._excluded_keys:
                continue
            if result.exe is not None and normalize(result.exe) in self._ignored:
                with self._lock:
                    self._ignored_count += 1
                continue
            if self._is_allowlisted(result):
                with self._lock:
                    self._allowlisted += 1
                continue
            key = (result.rule_id, result.process_key or result.exe or "-", result.dedup_key)
            if self._seen.get(key):
                with self._lock:
                    self._duplicates += 1
                continue
            self._seen.put(key, True)
            if event.event_id not in result.event_ids:
                result = result.model_copy(
                    update={"event_ids": (*result.event_ids, event.event_id)}
                )
            with self._lock:
                self._detections += 1
                self._recent.append(result)
            results.append(result)
            self._notify(result)
        return results

    def _is_allowlisted(self, result: DetectionResult) -> bool:
        with self._lock:
            allowlist = self._allowlist
        if allowlist is None or result.process_key is None:
            return False
        process = self._state.process(result.process_key)
        return process is not None and allowlist.allows(process, result.rule_id)

    def recent(self, process_key: str | None = None) -> list[DetectionResult]:
        with self._lock:
            items = list(self._recent)
        return items if process_key is None else [r for r in items if r.process_key == process_key]

    def stats(self) -> DetectionStats:
        with self._lock:
            return DetectionStats(
                rules_enabled=len(self._rules) - len(self._auto_disabled),
                evaluations=self._evaluations,
                detections=self._detections,
                duplicates_suppressed=self._duplicates,
                ignored=self._ignored_count + self._allowlisted,
                rule_errors=dict(self._rule_errors),
                auto_disabled=tuple(sorted(self._auto_disabled)),
            )

    def _record_failure(self, rule_id: str, event: SecurityEvent, exc: Exception) -> None:
        with self._lock:
            self._rule_errors[rule_id] = self._rule_errors.get(rule_id, 0) + 1
            failures = self._consecutive_failures.get(rule_id, 0) + 1
            self._consecutive_failures[rule_id] = failures
            disable = failures >= self._max_failures
            if disable:
                self._auto_disabled.add(rule_id)
        logger.warning(
            "event=RULE_FAILED rule=%s event_type=%s failures=%s error=%s",
            rule_id,
            event.event_type.value,
            failures,
            exc,
            exc_info=logger.isEnabledFor(logging.DEBUG),
        )
        if disable:
            logger.error(
                "event=RULE_AUTO_DISABLED rule=%s consecutive_failures=%s", rule_id, failures
            )

    def _notify(self, result: DetectionResult) -> None:
        for listener in self._listeners:
            try:
                listener(result)
            except Exception as exc:
                logger.warning(
                    "event=DETECTION_LISTENER_FAILED rule=%s error=%s", result.rule_id, exc
                )


LAUNCHER_NAMES: Final = frozenset(
    {"python.exe", "pythonw.exe", "py.exe", "winsentinel.exe", "threatlens.exe"}
)


def own_process_keys(processes: Sequence[ProcessInfo], pid: int) -> set[str]:
    """Process keys of this WinSentinel instance and its launcher chain.

    ``winsentinel.exe`` / ``threatlens.exe`` (pip's console-script stubs) start the venv's
    ``python.exe`` redirector, which starts the real interpreter. The packaged one-file
    ``ThreatLens.exe`` runs as a bootloader process that starts a second ``ThreatLens.exe``
    holding the interpreter. The walk stops at the first ancestor that is not one of those
    launchers, so the user's shell, terminal and everything above stay monitored. Only these
    exact running instances are excluded; another copy of the same file is still evaluated.
    """
    by_pid = {p.pid: p for p in processes}
    me = by_pid.get(pid)
    if me is None:
        return set()
    keys = {me.process_key}
    for ancestor in ancestry(me, by_pid):
        if ancestor.name.lower() not in LAUNCHER_NAMES:
            break
        keys.add(ancestor.process_key)
    return keys
