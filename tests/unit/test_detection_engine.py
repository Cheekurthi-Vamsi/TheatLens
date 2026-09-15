from __future__ import annotations

import pytest

from fixtures.detection import (
    CONTEXT,
    UNSIGNED,
    appeared,
    enriched,
    host,
    owned,
    proc,
    settings,
    socket_event,
)
from fixtures.fakes import minutes
from winsentinel.config import Config
from winsentinel.core.interfaces import StateView
from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
)
from winsentinel.detection.engine import DetectionEngine, own_process_keys
from winsentinel.detection.paths import PathClassifier
from winsentinel.detection.rules import build_rules
from winsentinel.detection.rules.base import Rule
from winsentinel.detection.scan import scan_process
from winsentinel.detection.settings import DetectionSettings

TEMP_EXE = r"C:\Users\alice\AppData\Local\Temp\x.exe"


class ExplodingRule(Rule):
    meta = RuleMetadata(
        rule_id="TEST-001",
        name="explodes",
        description="d",
        rationale="r",
        category=RuleCategory.ORIGIN,
        event_types=(EventType.PROCESS_STARTED,),
        base_score=5,
        confidence=Confidence.LOW,
        false_positives=("n/a",),
        recommendation="n/a",
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        raise RuntimeError("rule bug")


def test_routing_dedup_and_listener_notification() -> None:
    p = proc(20, "x.exe", TEMP_EXE)
    state = host([p])
    engine = DetectionEngine(build_rules(settings()), state)
    notified: list[DetectionResult] = []
    engine.subscribe(notified.append)

    first = engine.handle(appeared(p))
    again = engine.handle(appeared(p, EventType.PROCESS_DISCOVERED))
    assert [r.rule_id for r in first] == ["PROC-001"]
    assert again == []  # same finding for the same process instance is reported once
    assert notified == first
    assert first[0].event_ids  # traceable to the triggering event
    stats = engine.stats()
    assert (stats.detections, stats.duplicates_suppressed) == (1, 1)
    assert EventType.CONNECTION_OPENED in engine.event_types


def test_failing_rule_is_isolated_then_auto_disabled() -> None:
    p = proc(20, "x.exe", TEMP_EXE)
    rules = [ExplodingRule(settings()), *build_rules(settings())]
    engine = DetectionEngine(rules, host([p]), max_consecutive_failures=3)
    results = engine.handle(appeared(p))
    assert [r.rule_id for r in results] == ["PROC-001"]  # other rules unaffected
    for _ in range(3):
        engine.handle(appeared(p))
    stats = engine.stats()
    assert stats.rule_errors == {"TEST-001": 3}
    assert stats.auto_disabled == ("TEST-001",)


def test_disabled_rules_ignored_executables_and_self_exclusion() -> None:
    temp = proc(20, "x.exe", TEMP_EXE)
    ignored = proc(21, "y.exe", r"C:\Users\alice\AppData\Local\Temp\y.exe")
    myself = proc(22, "winsentinel.exe", r"C:\Users\alice\AppData\Local\Temp\winsentinel.exe")
    state = host([temp, ignored, myself])

    disabled = DetectionEngine(build_rules(settings()), state, disabled_rules={"PROC-001"})
    assert disabled.handle(appeared(temp)) == []
    assert "PROC-001" not in {m.rule_id for m in disabled.enabled_rules}

    engine = DetectionEngine(
        build_rules(settings()), state, ignored_executables={ignored.exe or ""}
    )
    engine.exclude_process_keys({myself.process_key})
    assert engine.handle(appeared(ignored)) == []
    assert engine.handle(appeared(myself)) == []
    assert engine.stats().ignored == 1
    copy = proc(
        23,
        "winsentinel.exe",
        r"C:\Users\alice\AppData\Local\Temp\winsentinel.exe",
        created=minutes(9.5),
    )
    assert DetectionEngine(build_rules(settings()), host([copy])).handle(
        appeared(copy)
    )  # a copy is still evaluated


def test_duplicate_rule_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        DetectionEngine([ExplodingRule(settings()), ExplodingRule(settings())], host([]))


def test_own_process_keys_stop_at_first_non_launcher() -> None:
    shell = proc(10, "powershell.exe", ppid=4, created=minutes(1))
    stub = proc(11, "winsentinel.exe", ppid=10, created=minutes(2))
    redirector = proc(12, "python.exe", ppid=11, created=minutes(3))
    interpreter = proc(13, "python.exe", ppid=12, created=minutes(4))
    keys = own_process_keys([shell, stub, redirector, interpreter], 13)
    assert keys == {stub.process_key, redirector.process_key, interpreter.process_key}


def test_own_process_keys_cover_pyinstaller_bootloader() -> None:
    explorer = proc(10, "explorer.exe", ppid=4, created=minutes(1))
    bootloader = proc(11, "ThreatLens.exe", ppid=10, created=minutes(2))
    interpreter = proc(12, "ThreatLens.exe", ppid=11, created=minutes(3))
    other_copy = proc(13, "ThreatLens.exe", ppid=10, created=minutes(4))
    keys = own_process_keys([explorer, bootloader, interpreter, other_copy], 12)
    assert keys == {bootloader.process_key, interpreter.process_key}


def test_scan_process_finds_static_and_timestamp_rules() -> None:
    word = proc(
        10,
        "winword.exe",
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        created=minutes(8),
    )
    payload = proc(
        20, "svchost.exe", TEMP_EXE.replace("x.exe", "svchost.exe"), ppid=10, created=minutes(9)
    )
    payload = payload.model_copy(update={"signature": UNSIGNED, "sha256": "ab" * 32})
    connection = owned(payload, "185.1.2.3", 4444)
    results = scan_process(payload, [word, payload], [connection], settings(), now=minutes(10))
    assert {r.rule_id for r in results} == {
        "PROC-001",
        "PROC-002",
        "PROC-005",
        "PROC-004",
        "NET-004",
    }


def test_settings_from_config() -> None:
    config = Config.model_validate(
        {
            "detection": {
                "disabled_rules": ["NET-004"],
                "common_remote_ports": [443],
                "ignored_executables": [r"C:\Tools\a.exe"],
            }
        }
    )
    built = DetectionSettings.from_config(config, CONTEXT)
    assert built.disabled_rules == frozenset({"NET-004"})
    assert built.common_remote_ports == frozenset({443})
    assert built.ignored_executables == frozenset({r"c:\tools\a.exe"})
    assert isinstance(built.paths, PathClassifier)


def test_enriched_event_without_state_is_harmless() -> None:
    p = proc(20, "x.exe")
    engine = DetectionEngine(build_rules(settings()), host([]))
    assert engine.handle(enriched(p)) == []
    assert engine.handle(socket_event(owned(p))) == []


def test_allowlist_suppresses_matching_process() -> None:
    from winsentinel.detection.allowlist import AllowlistEntry, AllowlistMatcher, AllowlistMatchType

    temp = proc(20, "x.exe", TEMP_EXE)
    state = host([temp])
    engine = DetectionEngine(build_rules(settings()), state)
    assert engine.handle(appeared(temp))  # fires PROC-001 without an allowlist
    engine.set_allowlist(AllowlistMatcher([AllowlistEntry(AllowlistMatchType.EXE_PATH, TEMP_EXE)]))
    # A fresh subject (new process instance) is now suppressed.
    other = proc(21, "x.exe", TEMP_EXE, created=minutes(9.5))
    assert DetectionEngine(build_rules(settings()), host([other])).handle(
        appeared(other)
    )  # control
    engine2 = DetectionEngine(build_rules(settings()), host([other]))
    engine2.set_allowlist(AllowlistMatcher([AllowlistEntry(AllowlistMatchType.EXE_PATH, TEMP_EXE)]))
    assert engine2.handle(appeared(other)) == []
