"""Persistence rules: new autostart entries added after monitoring began."""

from __future__ import annotations

from typing import Final

from winsentinel.core.interfaces import StateView
from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
)
from winsentinel.detection.rules.base import Rule, inferred, observed

_KIND_LABEL: Final = {
    "REGISTRY_RUN": "a registry Run key",
    "STARTUP_FOLDER": "the Startup folder",
    "SCHEDULED_TASK": "a scheduled task",
    "SERVICE": "an auto-start service",
}


class NewAutorunEntry(Rule):
    meta = RuleMetadata(
        rule_id="PERSIST-001",
        name="New autostart entry",
        description=(
            "A new registry Run key or Startup-folder entry appeared after monitoring began."
        ),
        rationale=(
            "Establishing autostart is how malware survives a reboot. A Run key or Startup "
            "entry that appears while WinSentinel is watching is worth confirming; the risk is "
            "higher when the program it points at lives in a user-writable or temporary location."
        ),
        category=RuleCategory.PERSISTENCE,
        event_types=(EventType.PERSISTENCE_ADDED,),
        base_score=30,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1547.001",),
        false_positives=(
            "Installing or updating legitimate software that adds a startup entry",
            "The user pinning an application to run at login",
        ),
        recommendation=(
            "Confirm you installed or expected this program. Remove the entry (regedit or the "
            "Startup folder) if it is unwanted; WinSentinel only reports, never modifies it."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        data = event.data
        if data.get("kind") not in ("REGISTRY_RUN", "STARTUP_FOLDER"):
            return None
        executable = data.get("executable")
        location = _KIND_LABEL.get(str(data.get("kind")), "an autostart location")
        evidence = [
            observed(
                f"New autostart entry '{data.get('name')}' in {location}",
                "location",
                data.get("location"),
            ),
        ]
        if data.get("command"):
            evidence.append(observed("Command", "command", data.get("command")))
        score, confidence = 20, Confidence.LOW
        if executable and self.settings.paths.user_writable_location(str(executable)):
            writable = self.settings.paths.user_writable_location(str(executable))
            evidence.append(inferred(f"Its program is in {writable}", "executable", executable))
            score, confidence = 30, Confidence.MEDIUM
        return self.result(
            process=None,
            evidence=evidence,
            detail=f"new autostart entry '{data.get('name')}' in {location}",
            event=event,
            score=score,
            confidence=confidence,
            dedup_key=str(data.get("item_key")),
        )


class NewScheduledTaskOrService(Rule):
    meta = RuleMetadata(
        rule_id="PERSIST-002",
        name="New scheduled task or auto-start service",
        description="A new scheduled task or auto-start service appeared after monitoring began.",
        rationale=(
            "Scheduled tasks and services are stealthier persistence than Run keys and are common "
            "in intrusions. A new one pointing at a user-writable or temporary executable is a "
            "strong signal; one in a protected location is usually a software install."
        ),
        category=RuleCategory.PERSISTENCE,
        event_types=(EventType.PERSISTENCE_ADDED,),
        base_score=35,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1053.005", "T1543.003"),
        false_positives=(
            "Installing software that registers a service or scheduled task",
            "Windows or driver updates adding maintenance tasks",
        ),
        recommendation=(
            "Verify the task/service is from software you installed. Its executable and command "
            "line are in the evidence; investigate if it runs from a user-writable location."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        data = event.data
        if data.get("kind") not in ("SCHEDULED_TASK", "SERVICE"):
            return None
        label = _KIND_LABEL.get(str(data.get("kind")), "an autostart mechanism")
        executable = data.get("executable")
        evidence = [
            observed(f"New {label}: '{data.get('name')}'", "name", data.get("name")),
        ]
        if data.get("command"):
            evidence.append(observed("Command", "command", data.get("command")))
        score, confidence = 20, Confidence.LOW
        if executable and self.settings.paths.user_writable_location(str(executable)):
            writable = self.settings.paths.user_writable_location(str(executable))
            evidence.append(inferred(f"Its executable is in {writable}", "executable", executable))
            score, confidence = 35, Confidence.MEDIUM
        return self.result(
            process=None,
            evidence=evidence,
            detail=f"new {label} '{data.get('name')}'",
            event=event,
            score=score,
            confidence=confidence,
            dedup_key=str(data.get("item_key")),
        )
