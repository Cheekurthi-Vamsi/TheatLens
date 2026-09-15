from __future__ import annotations

from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    Evidence,
    NetworkContext,
    RuleCategory,
    Severity,
)
from winsentinel.core.models.alert import AlertStatus
from winsentinel.detection.alerting import AlertManager, build_alert
from winsentinel.detection.scoring import score_detections


def detection(
    rule_id: str,
    category: RuleCategory,
    score: int,
    confidence: Confidence,
    *,
    process_key: str = "20:0",
    network: tuple[NetworkContext, ...] = (),
) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_id,
        category=category,
        score=score,
        confidence=confidence,
        summary=f"{rule_id} fired",
        evidence=(Evidence(description="x"),),
        process_key=process_key,
        pid=20,
        process_name="suspicious.exe",
        exe=r"C:\Users\a\AppData\Local\Temp\suspicious.exe",
        network=network,
    )


def test_architecture_worked_example_scores_70_high() -> None:
    # docs/architecture.md §11: temp(20/HIGH) + unsigned(15/HIGH) + parent(25/MEDIUM->18.75)
    # + external(20/MEDIUM->15) + unusual-port(10/LOW->5), 4 categories -> +15 -> 70 HIGH.
    detections = [
        detection("PROC-001", RuleCategory.ORIGIN, 20, Confidence.HIGH),
        detection("PROC-002", RuleCategory.SIGNATURE, 15, Confidence.HIGH),
        detection("PROC-003", RuleCategory.LINEAGE, 25, Confidence.MEDIUM),
        detection("PROC-004", RuleCategory.NETWORK, 20, Confidence.MEDIUM),
        detection("NET-004", RuleCategory.NETWORK, 10, Confidence.LOW),
    ]
    risk = score_detections(detections)
    assert risk.score == 70
    assert risk.severity is Severity.HIGH
    assert risk.confidence is Confidence.HIGH  # two HIGH rules across two categories


def test_single_weak_signal_stays_normal_or_low() -> None:
    risk = score_detections([detection("NET-004", RuleCategory.NETWORK, 10, Confidence.LOW)])
    assert risk.score == 5 and risk.severity is Severity.NORMAL


def test_all_low_confidence_is_capped_at_low() -> None:
    detections = [
        detection("AA-001", RuleCategory.NETWORK, 20, Confidence.LOW),
        detection("BB-001", RuleCategory.ORIGIN, 20, Confidence.LOW),
        detection("CC-001", RuleCategory.SIGNATURE, 20, Confidence.LOW),
        detection("DD-001", RuleCategory.LINEAGE, 20, Confidence.LOW),
    ]
    risk = score_detections(detections)
    assert risk.score <= 39 and risk.severity is Severity.LOW


def test_single_category_is_capped_at_medium() -> None:
    detections = [
        detection("AA-001", RuleCategory.NETWORK, 45, Confidence.HIGH),
        detection("BB-001", RuleCategory.NETWORK, 45, Confidence.HIGH),
        detection("CC-001", RuleCategory.NETWORK, 45, Confidence.HIGH),
    ]
    risk = score_detections(detections)
    assert risk.score == 59 and risk.severity is Severity.MEDIUM


def test_duplicate_rule_firings_do_not_stack() -> None:
    once = score_detections([detection("PROC-004", RuleCategory.NETWORK, 20, Confidence.MEDIUM)])
    twice = score_detections(
        [
            detection("PROC-004", RuleCategory.NETWORK, 20, Confidence.MEDIUM),
            detection("PROC-004", RuleCategory.NETWORK, 20, Confidence.MEDIUM),
        ]
    )
    assert once.score == twice.score


def test_empty_is_zero() -> None:
    assert score_detections([]).score == 0


class TestAlertManager:
    def make(self, threshold: int = 40) -> AlertManager:
        return AlertManager(threshold)

    def test_below_threshold_raises_no_alert(self) -> None:
        manager = self.make()
        assert (
            manager.handle(detection("NET-004", RuleCategory.NETWORK, 10, Confidence.LOW)) is None
        )
        assert manager.alerts() == []

    def test_accumulating_detections_crosses_threshold(self) -> None:
        manager = self.make()
        assert (
            manager.handle(detection("PROC-001", RuleCategory.ORIGIN, 20, Confidence.HIGH)) is None
        )
        alert = manager.handle(detection("PROC-005", RuleCategory.MASQUERADE, 45, Confidence.HIGH))
        assert alert is not None and alert.risk_score >= 40
        assert set(alert.rules_triggered) == {"PROC-001", "PROC-005"}
        assert manager.raised == 1

    def test_alert_identity_is_stable_across_updates(self) -> None:
        manager = self.make()
        first = manager.handle(detection("PROC-005", RuleCategory.MASQUERADE, 45, Confidence.HIGH))
        second = manager.handle(detection("PROC-001", RuleCategory.ORIGIN, 20, Confidence.HIGH))
        assert first is not None and second is not None
        assert first.alert_id == second.alert_id
        assert first.created_at == second.created_at
        assert manager.raised == 1

    def test_status_transitions_are_preserved(self) -> None:
        manager = self.make()
        alert = manager.handle(detection("PROC-005", RuleCategory.MASQUERADE, 45, Confidence.HIGH))
        assert alert is not None
        manager.set_status(alert.alert_id, AlertStatus.RESOLVED)
        updated = manager.handle(detection("PROC-001", RuleCategory.ORIGIN, 20, Confidence.HIGH))
        assert updated is not None and updated.status is AlertStatus.RESOLVED
        assert manager.active_count == 0

    def test_build_alert_recommendations_depend_on_running_and_score(self) -> None:
        detections = [detection("PROC-005", RuleCategory.MASQUERADE, 45, Confidence.HIGH)]
        running = build_alert("20:0", detections, running=True)
        stopped = build_alert("20:0", detections, running=False)
        assert running is not None and any(
            "suspend" in a.lower() for a in running.recommended_actions
        )
        assert stopped is not None and not any(
            "suspend" in a.lower() for a in stopped.recommended_actions
        )
