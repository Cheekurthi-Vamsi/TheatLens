"""Risk scoring: combine several rule detections into one explainable score.

Design (docs/architecture.md §11). The goals are: explainable, conservative, **not a blind
sum**, and resistant to many weak signals piling up into CRITICAL.

1. **Effective contribution** per rule: ``raw_score * confidence_weight``. Duplicate firings of
   the same rule do not stack -- the highest-scoring detection per ``rule_id`` is kept.
2. **Noisy-OR combination** (diminishing returns, capped at 100):
   ``combined = 100 * (1 - product(1 - effective_i/100))``.
3. **Corroboration bonus**: independent *categories* agreeing is stronger than one category
   firing many ways -- ``min(15, 5 * (distinct_categories - 1))``.
4. **Caps**: all-LOW-confidence contributions cap at 39 (LOW); a single category caps at 59
   (MEDIUM). So one rule, however weak, cannot alone produce HIGH/CRITICAL.

The worked example in the architecture doc is reproduced by ``tests/unit/test_scoring.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from winsentinel.core.models import Confidence, DetectionResult, Severity, severity_for_score
from winsentinel.core.models.alert import ScoreContribution

CONFIDENCE_WEIGHT: Final[dict[Confidence, float]] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.5,
}
ALL_LOW_CAP: Final = 39
SINGLE_CATEGORY_CAP: Final = 59
MAX_BONUS: Final = 15
BONUS_PER_EXTRA_CATEGORY: Final = 5


@dataclass(frozen=True, slots=True)
class RiskScore:
    score: int
    confidence: Confidence
    contributions: tuple[ScoreContribution, ...]

    @property
    def severity(self) -> Severity:
        return severity_for_score(self.score)


def _dedupe_highest_per_rule(detections: list[DetectionResult]) -> list[DetectionResult]:
    best: dict[str, DetectionResult] = {}
    for detection in detections:
        current = best.get(detection.rule_id)
        if current is None or detection.score > current.score:
            best[detection.rule_id] = detection
    return list(best.values())


def _contribution(detection: DetectionResult) -> ScoreContribution:
    weight = CONFIDENCE_WEIGHT[detection.confidence]
    return ScoreContribution(
        rule_id=detection.rule_id,
        rule_name=detection.rule_name,
        category=detection.category.value,
        raw_score=detection.score,
        confidence=detection.confidence,
        effective=round(detection.score * weight, 3),
        detection_id=detection.detection_id,
    )


def _alert_confidence(contributions: list[ScoreContribution]) -> Confidence:
    high = [c for c in contributions if c.confidence is Confidence.HIGH]
    categories_of_high = {c.category for c in high}
    if len(high) >= 2 and len(categories_of_high) >= 2:
        return Confidence.HIGH
    if len(contributions) >= 2 or high:
        return Confidence.MEDIUM
    return Confidence.LOW


def score_detections(detections: list[DetectionResult]) -> RiskScore:
    """Combine ``detections`` (assumed to be for one subject) into a :class:`RiskScore`."""
    if not detections:
        return RiskScore(score=0, confidence=Confidence.LOW, contributions=())

    contributions = sorted(
        (_contribution(d) for d in _dedupe_highest_per_rule(detections)),
        key=lambda c: (-c.effective, c.rule_id),
    )

    product = 1.0
    for contribution in contributions:
        product *= 1.0 - min(contribution.effective, 100.0) / 100.0
    combined = 100.0 * (1.0 - product)

    categories = {c.category for c in contributions}
    bonus = min(MAX_BONUS, BONUS_PER_EXTRA_CATEGORY * (len(categories) - 1))
    score = min(100, round(combined + bonus))

    if all(c.confidence is Confidence.LOW for c in contributions):
        score = min(score, ALL_LOW_CAP)
    if len(categories) == 1:
        score = min(score, SINGLE_CATEGORY_CAP)

    return RiskScore(
        score=score, confidence=_alert_confidence(contributions), contributions=tuple(contributions)
    )
