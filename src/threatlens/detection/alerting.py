"""Turn a stream of detections into scored, de-duplicated alerts per process instance.

One alert exists per process instance (``process_key``). As new detections arrive for that
process the alert's score is recomputed from *all* its detections and, if it crosses the
threshold, the alert is (re)emitted. User-set statuses are respected: an alert the user marked
``RESOLVED`` or ``IGNORED`` is not silently reopened, though its evidence keeps accumulating.
Memory is bounded (LRU over process keys).
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Final

from threatlens.core.models import DetectionResult, NetworkContext
from threatlens.core.models.alert import TERMINAL_STATUSES, Alert, AlertStatus
from threatlens.detection.scoring import RiskScore, score_detections
from threatlens.utils.time import utc_now

AlertListener = Callable[[Alert], None]
DEFAULT_MAX_ALERTS: Final = 2000


def recommended_actions(risk: RiskScore, running: bool) -> tuple[str, ...]:
    """Human-in-the-loop next steps; deliberately conservative and never automatic."""
    actions = ["Inspect the process with 'threatlens inspect <PID>'"]
    if running:
        actions.append(
            "Suspend it to freeze activity while you investigate: 'threatlens suspend <PID>'"
        )
        if risk.score >= 60:
            actions.append(
                "Terminate it if you confirm it is unwanted: 'threatlens terminate <PID>'"
            )
    actions.append("If it is expected, allowlist it by path or SHA256 (see 'threatlens allow')")
    return tuple(actions)


def build_alert(
    process_key: str | None,
    detections: list[DetectionResult],
    *,
    running: bool,
    created_at: object = None,
    status: AlertStatus = AlertStatus.NEW,
    alert_id: str | None = None,
) -> Alert | None:
    """Construct an :class:`Alert` from all detections for one subject, or ``None`` if none."""
    if not detections:
        return None
    risk = score_detections(detections)
    representative = max(detections, key=lambda d: d.score)
    now = utc_now()
    network: list[NetworkContext] = []
    seen: set[tuple[object, ...]] = set()
    for detection in detections:
        for context in detection.network:
            key = (
                context.protocol,
                context.remote_address,
                context.remote_port,
                context.local_port,
            )
            if key not in seen:
                seen.add(key)
                network.append(context)
    fields = {
        "created_at": created_at or now,
        "updated_at": now,
        "title": _title(representative, risk),
        "risk_score": risk.score,
        "confidence": risk.confidence,
        "status": status,
        "process_key": process_key,
        "pid": representative.pid,
        "process_name": representative.process_name,
        "exe": representative.exe,
        "detections": tuple(sorted(detections, key=lambda d: -d.score)),
        "score_breakdown": risk.contributions,
        "network": tuple(network),
        "recommended_actions": recommended_actions(risk, running),
    }
    if alert_id is not None:
        fields["alert_id"] = alert_id
    return Alert.model_validate(fields)


def _title(detection: DetectionResult, risk: RiskScore) -> str:
    who = detection.process_name or "Unattributed activity"
    return f"{risk.severity.value} risk: {who} — {len(risk.contributions)} indicator(s)"


class AlertManager:
    """Thread-safe: the dispatcher thread feeds detections; readers include the dashboard."""

    def __init__(
        self,
        threshold: int,
        *,
        max_alerts: int = DEFAULT_MAX_ALERTS,
        running_check: Callable[[str], bool] | None = None,
    ) -> None:
        self._threshold = threshold
        self._max = max_alerts
        self._running_check = running_check or (lambda _key: True)
        self._detections: OrderedDict[str, list[DetectionResult]] = OrderedDict()
        self._alerts: dict[str, Alert] = {}
        self._listeners: list[AlertListener] = []
        self._lock = threading.Lock()
        self._raised = 0

    def subscribe(self, listener: AlertListener) -> None:
        self._listeners.append(listener)

    def handle(self, detection: DetectionResult) -> Alert | None:
        """Accumulate a detection and (re)emit the subject's alert if it crosses the threshold."""
        key = detection.process_key or f"exe:{detection.exe or detection.rule_id}"
        with self._lock:
            bucket = self._detections.get(key)
            if bucket is None:
                bucket = []
                self._detections[key] = bucket
                while len(self._detections) > self._max:
                    old, _ = self._detections.popitem(last=False)
                    self._alerts.pop(old, None)
            self._detections.move_to_end(key)
            bucket.append(detection)
            existing = self._alerts.get(key)
            running = self._running_check(detection.process_key) if detection.process_key else True
            alert = build_alert(
                detection.process_key,
                list(bucket),
                running=running,
                created_at=existing.created_at if existing else None,
                status=existing.status if existing else AlertStatus.NEW,
                alert_id=existing.alert_id if existing else None,
            )
            if alert is None or alert.risk_score < self._threshold:
                return None
            is_new = existing is None
            self._alerts[key] = alert
            if is_new:
                self._raised += 1
        for listener in self._listeners:
            listener(alert)
        return alert

    def alerts(self) -> list[Alert]:
        with self._lock:
            return sorted(self._alerts.values(), key=lambda a: (-a.risk_score, a.updated_at))

    def get(self, alert_id: str) -> Alert | None:
        with self._lock:
            return next((a for a in self._alerts.values() if a.alert_id == alert_id), None)

    def set_status(self, alert_id: str, status: AlertStatus) -> Alert | None:
        with self._lock:
            for key, alert in self._alerts.items():
                if alert.alert_id == alert_id:
                    updated = alert.model_copy(update={"status": status, "updated_at": utc_now()})
                    self._alerts[key] = updated
                    return updated
            return None

    @property
    def raised(self) -> int:
        with self._lock:
            return self._raised

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._alerts.values() if a.status not in TERMINAL_STATUSES)
