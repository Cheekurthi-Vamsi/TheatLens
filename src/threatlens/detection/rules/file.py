"""File-activity rules."""

from __future__ import annotations

from threatlens.core.interfaces import StateView
from threatlens.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
)
from threatlens.detection.rules.base import Rule, inferred, observed


class ExecutableDroppedInSensitiveLocation(Rule):
    meta = RuleMetadata(
        rule_id="FILE-001",
        name="Executable or script written to a monitored sensitive location",
        description=(
            "An executable or script file was created in a monitored security-relevant directory "
            "(a Startup folder, %TEMP%, or Downloads)."
        ),
        rationale=(
            "Malware stages payloads by writing an executable to Temp, and establishes "
            "persistence by dropping one into a Startup folder. Seeing a new .exe/.dll/.ps1/.scr "
            "appear there is an early signal — well before it necessarily runs. It is only a "
            "signal: browsers and installers legitimately write executables to these places."
        ),
        category=RuleCategory.PERSISTENCE,
        event_types=(EventType.FILE_CREATED, EventType.FILE_RENAMED),
        base_score=30,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1105", "T1547.001"),
        false_positives=(
            "Downloading an installer or program (lands in Downloads)",
            "Installers and self-extracting archives unpacking to %TEMP%",
            "A user placing a shortcut in their Startup folder",
        ),
        recommendation=(
            "Correlate with process activity: if a new process then runs this file, or it appears "
            "in a Startup folder you did not populate, investigate its origin."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        data = event.data
        if not data.get("executable_or_script"):
            return None
        path = str(data.get("path", ""))
        lowered = path.lower()
        in_startup = "\\startup" in lowered
        location = "a Startup folder" if in_startup else "a monitored location"
        evidence = [
            observed(f"{data.get('name')} was created in {location}", "path", path),
        ]
        if data.get("from"):
            evidence.append(observed("Renamed from", "from", data.get("from")))
        score, confidence = (30, Confidence.MEDIUM) if in_startup else (20, Confidence.LOW)
        if in_startup:
            evidence.append(
                inferred("A file placed in a Startup folder runs automatically at the next logon")
            )
        return self.result(
            process=None,
            evidence=evidence,
            detail=f"{data.get('name')} written to {location}",
            event=event,
            score=score,
            confidence=confidence,
            dedup_key=lowered,
        )
