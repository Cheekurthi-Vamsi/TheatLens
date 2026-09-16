"""Typed read/write access over the SQLite schema.

Writes derive process, connection, detection and alert rows from the models the engine already
produces. All statements are parameterized. Upserts key on the stable identities defined in the
models (``process_key``, ``connection_key``, ``alert_id``), so re-observing the same entity
updates it rather than duplicating it.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from threatlens.core.models import (
    Alert,
    AlertStatus,
    Confidence,
    DetectionResult,
    EventType,
    NetworkContext,
    ResponseAction,
    ScoreContribution,
    SecurityEvent,
    Severity,
)
from threatlens.storage.database import Database, dumps, loads
from threatlens.utils.time import utc_now


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else value.isoformat()


class SecurityStore:
    """All persistence for the engine and CLI. Not thread-safe; one per owning thread."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # -- writes -----------------------------------------------------------------------------

    def record_event(self, event: SecurityEvent) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO security_events "
            "(event_id, schema_version, event_type, timestamp, source, observation, "
            " process_key, pid, data) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                event.event_id,
                event.schema_version,
                event.event_type.value,
                event.timestamp.isoformat(),
                event.source,
                event.observation.value,
                event.process_key,
                event.pid,
                dumps(event.data),
            ),
        )
        self._apply_event_side_effects(event)

    def _apply_event_side_effects(self, event: SecurityEvent) -> None:
        data = event.data
        if event.event_type in (EventType.PROCESS_DISCOVERED, EventType.PROCESS_STARTED):
            self._upsert_process(event, data)
        elif event.event_type is EventType.PROCESS_STOPPED and event.process_key:
            self.db.execute(
                "UPDATE processes SET exited_at=?, last_seen=? WHERE process_key=?",
                (
                    _iso(data.get("exited_before")) or event.timestamp.isoformat(),
                    event.timestamp.isoformat(),
                    event.process_key,
                ),
            )
        elif event.event_type is EventType.PROCESS_ENRICHED and event.process_key:
            self.db.execute(
                "UPDATE processes SET sha256=?, signature_status=?, signer=?, last_seen=? "
                "WHERE process_key=?",
                (
                    data.get("sha256"),
                    data.get("signature_status"),
                    data.get("signer"),
                    event.timestamp.isoformat(),
                    event.process_key,
                ),
            )
        elif event.event_type.value.startswith(("CONNECTION_", "LISTENER_")):
            self._upsert_connection(event, data)
        elif event.event_type.value.startswith("PERSISTENCE_"):
            self._apply_persistence(event, data)

    def _apply_persistence(self, event: SecurityEvent, data: dict[str, Any]) -> None:
        key = data.get("item_key")
        if not key:
            return
        now = event.timestamp.isoformat()
        if event.event_type.value == "PERSISTENCE_REMOVED":
            self.db.execute(
                "UPDATE persistence_items SET removed_at=? WHERE item_key=? AND removed_at IS NULL",
                (now, key),
            )
            return
        self.db.execute(
            "INSERT INTO persistence_items "
            "(item_key, kind, location, name, command, executable, arguments, "
            " first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(item_key) DO UPDATE SET last_seen=excluded.last_seen, "
            " command=excluded.command, removed_at=NULL",
            (
                key,
                data.get("kind"),
                data.get("location"),
                data.get("name"),
                data.get("command"),
                data.get("executable"),
                data.get("arguments"),
                now,
                now,
            ),
        )

    def _upsert_process(self, event: SecurityEvent, data: dict[str, Any]) -> None:
        now = event.timestamp.isoformat()
        cmdline = data.get("cmdline")
        self.db.execute(
            "INSERT INTO processes "
            "(process_key, pid, ppid, parent_key, name, exe, cmdline, username, create_time, "
            " integrity_level, session_id, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(process_key) DO UPDATE SET last_seen=excluded.last_seen",
            (
                event.process_key,
                event.pid,
                data.get("ppid"),
                data.get("parent_key"),
                data.get("name", "?"),
                data.get("exe"),
                " ".join(cmdline) if isinstance(cmdline, list) else None,
                data.get("username"),
                _iso(data.get("create_time")),
                data.get("integrity_level"),
                data.get("session_id"),
                now,
                now,
            ),
        )

    def _upsert_connection(self, event: SecurityEvent, data: dict[str, Any]) -> None:
        key = data.get("connection_key")
        if not key:
            return
        now = event.timestamp.isoformat()
        closed = now if event.event_type.value.endswith("_CLOSED") else None
        self.db.execute(
            "INSERT INTO network_connections "
            "(connection_key, process_key, pid, protocol, family, local_address, local_port, "
            " remote_address, remote_port, state, direction, remote_scope, owner_module, "
            " created_at, first_seen, last_seen, closed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(connection_key) DO UPDATE SET last_seen=excluded.last_seen, "
            " state=excluded.state, "
            " closed_at=COALESCE(excluded.closed_at, network_connections.closed_at)",
            (
                key,
                data.get("process_key"),
                data.get("pid"),
                data.get("protocol"),
                data.get("family"),
                data.get("local_address"),
                data.get("local_port"),
                data.get("remote_address"),
                data.get("remote_port"),
                data.get("state"),
                data.get("direction"),
                data.get("remote_scope"),
                data.get("owner_module"),
                _iso(data.get("created_at")),
                now,
                now,
                closed,
            ),
        )

    def record_detection(self, detection: DetectionResult, alert_id: str | None = None) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO detections "
            "(detection_id, alert_id, rule_id, timestamp, process_key, pid, process_name, exe, "
            " score, confidence, category, summary, evidence, network, mitre, event_ids) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                detection.detection_id,
                alert_id,
                detection.rule_id,
                detection.timestamp.isoformat(),
                detection.process_key,
                detection.pid,
                detection.process_name,
                detection.exe,
                detection.score,
                detection.confidence.value,
                detection.category.value,
                detection.summary,
                dumps([e.model_dump(mode="json") for e in detection.evidence]),
                dumps([n.model_dump(mode="json") for n in detection.network]),
                dumps(list(detection.mitre_techniques)),
                dumps(list(detection.event_ids)),
            ),
        )

    def upsert_alert(self, alert: Alert) -> None:
        self.db.execute(
            "INSERT INTO alerts "
            "(alert_id, created_at, updated_at, title, severity, confidence, risk_score, status, "
            " process_key, pid, process_name, exe, network, score_breakdown, rules_triggered, "
            " recommended_actions, detections) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(alert_id) DO UPDATE SET updated_at=excluded.updated_at, "
            " risk_score=excluded.risk_score, confidence=excluded.confidence, "
            " severity=excluded.severity, title=excluded.title, network=excluded.network, "
            " score_breakdown=excluded.score_breakdown, rules_triggered=excluded.rules_triggered, "
            " recommended_actions=excluded.recommended_actions, detections=excluded.detections, "
            " status=CASE WHEN alerts.status IN ('RESOLVED','IGNORED') "
            "   THEN alerts.status ELSE excluded.status END",
            (
                alert.alert_id,
                alert.created_at.isoformat(),
                alert.updated_at.isoformat(),
                alert.title,
                alert.severity.value,
                alert.confidence.value,
                alert.risk_score,
                alert.status.value,
                alert.process_key,
                alert.pid,
                alert.process_name,
                alert.exe,
                dumps([n.model_dump(mode="json") for n in alert.network]),
                dumps([c.model_dump(mode="json") for c in alert.score_breakdown]),
                dumps(list(alert.rules_triggered)),
                dumps(list(alert.recommended_actions)),
                dumps([d.detection_id for d in alert.detections]),
            ),
        )
        for detection in alert.detections:
            self.db.execute(
                "UPDATE detections SET alert_id=? WHERE detection_id=?",
                (alert.alert_id, detection.detection_id),
            )

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        cursor = self.db.execute(
            "UPDATE alerts SET status=?, updated_at=? WHERE alert_id=? OR alert_id LIKE ?",
            (status, utc_now().isoformat(), alert_id, f"{alert_id}%"),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def record_action(self, action: ResponseAction) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO actions "
            "(action_id, timestamp, action_type, target, process_key, pid, reason, requested_by, "
            " outcome, error, reverses_action_id, details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                action.action_id,
                action.timestamp.isoformat(),
                action.action_type.value,
                action.target,
                action.process_key,
                action.pid,
                action.reason,
                action.requested_by,
                action.outcome.value,
                action.error,
                action.reverses_action_id,
                dumps(action.details),
            ),
        )
        self.db.commit()

    def record_firewall_rule(
        self, rule_name: str, action_id: str, target_type: str, target: str, direction: str
    ) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO firewall_rules "
            "(rule_name, action_id, target_type, target, direction, created_at, removed_at) "
            "VALUES (?,?,?,?,?,?,NULL)",
            (rule_name, action_id, target_type, target, direction, utc_now().isoformat()),
        )
        self.db.commit()

    def mark_firewall_rule_removed(self, rule_name: str) -> None:
        self.db.execute(
            "UPDATE firewall_rules SET removed_at=? WHERE rule_name=? AND removed_at IS NULL",
            (utc_now().isoformat(), rule_name),
        )
        self.db.commit()

    def firewall_rules(self, *, active_only: bool = True) -> list[sqlite3.Row]:
        clause = "WHERE removed_at IS NULL" if active_only else ""
        return self.db.query(
            f"SELECT * FROM firewall_rules {clause} ORDER BY created_at DESC"  # noqa: S608
        )

    # -- baselines --------------------------------------------------------------------------

    def create_baseline(
        self,
        baseline_id: str,
        name: str,
        *,
        created_by: str,
        hostname: str,
        expires_at: str | None,
        notes: str | None,
        items: Sequence[tuple[str, str, str, dict[str, Any]]],
    ) -> None:
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO baselines "
                "(baseline_id, name, created_at, expires_at, created_by, hostname, "
                " notes, item_count) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    baseline_id,
                    name,
                    utc_now().isoformat(),
                    expires_at,
                    created_by,
                    hostname,
                    notes,
                    len(items),
                ),
            )
            self.db.executemany(
                "INSERT INTO baseline_items (baseline_id, kind, item_key, label, attributes) "
                "VALUES (?,?,?,?,?)",
                [
                    (baseline_id, kind, key, label, dumps(attrs))
                    for kind, key, label, attrs in items
                ],
            )

    def baselines(self) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM baselines ORDER BY created_at DESC")

    def baseline(self, baseline_id: str) -> sqlite3.Row | None:
        return self.db.query_one(
            "SELECT * FROM baselines WHERE baseline_id=? OR baseline_id LIKE ? "
            "ORDER BY created_at DESC LIMIT 1",
            (baseline_id, f"{baseline_id}%"),
        )

    def latest_baseline(self) -> sqlite3.Row | None:
        return self.db.query_one("SELECT * FROM baselines ORDER BY created_at DESC LIMIT 1")

    def baseline_items(self, baseline_id: str) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM baseline_items WHERE baseline_id=?", (baseline_id,))

    def delete_baseline(self, baseline_id: str) -> bool:
        cursor = self.db.execute("DELETE FROM baselines WHERE baseline_id=?", (baseline_id,))
        self.db.commit()
        return cursor.rowcount > 0

    # -- allowlist --------------------------------------------------------------------------

    def add_allowlist_entry(
        self,
        match_type: str,
        value: str,
        *,
        rule_ids: str | None,
        reason: str,
        created_by: str,
        expires_at: str | None,
    ) -> None:
        self.db.execute(
            "INSERT INTO allowlist_entries "
            "(match_type, value, rule_ids, reason, created_at, created_by, expires_at) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(match_type, value) DO UPDATE SET rule_ids=excluded.rule_ids, "
            " reason=excluded.reason, expires_at=excluded.expires_at",
            (match_type, value, rule_ids, reason, utc_now().isoformat(), created_by, expires_at),
        )
        self.db.commit()

    def allowlist_entries(self) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM allowlist_entries ORDER BY created_at DESC")

    def remove_allowlist_entry(self, match_type: str, value: str) -> bool:
        cursor = self.db.execute(
            "DELETE FROM allowlist_entries WHERE match_type=? AND value=?", (match_type, value)
        )
        self.db.commit()
        return cursor.rowcount > 0

    def record_config(self, source_path: str, content: str) -> None:
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        existing = self.db.query_one(
            "SELECT config_sha256 FROM configuration_history ORDER BY id DESC LIMIT 1"
        )
        if existing is not None and existing["config_sha256"] == digest:
            return
        self.db.execute(
            "INSERT INTO configuration_history (timestamp, config_sha256, source_path, content) "
            "VALUES (?,?,?,?)",
            (utc_now().isoformat(), digest, source_path, content),
        )
        self.db.commit()

    # -- retention --------------------------------------------------------------------------

    def apply_retention(
        self, event_days: int, alert_days: int, action_days: int, *, now: datetime | None = None
    ) -> dict[str, int]:
        moment = now or utc_now()
        deleted: dict[str, int] = {}
        if event_days > 0:
            cutoff = (moment - timedelta(days=event_days)).isoformat()
            deleted["security_events"] = self.db.execute(
                "DELETE FROM security_events WHERE timestamp < ?", (cutoff,)
            ).rowcount
            deleted["detections"] = self.db.execute(
                "DELETE FROM detections WHERE timestamp < ? AND alert_id IS NULL", (cutoff,)
            ).rowcount
            deleted["network_connections"] = self.db.execute(
                "DELETE FROM network_connections WHERE COALESCE(closed_at, last_seen) < ?",
                (cutoff,),
            ).rowcount
            deleted["processes"] = self.db.execute(
                "DELETE FROM processes WHERE exited_at IS NOT NULL AND exited_at < ?", (cutoff,)
            ).rowcount
        if alert_days > 0:
            cutoff = (moment - timedelta(days=alert_days)).isoformat()
            deleted["alerts"] = self.db.execute(
                "DELETE FROM alerts WHERE updated_at < ? AND status IN ('RESOLVED','IGNORED')",
                (cutoff,),
            ).rowcount
        if action_days > 0:
            cutoff = (moment - timedelta(days=action_days)).isoformat()
            deleted["actions"] = self.db.execute(
                "DELETE FROM actions WHERE timestamp < ?", (cutoff,)
            ).rowcount
        self.db.commit()
        return {k: v for k, v in deleted.items() if v}

    # -- reads ------------------------------------------------------------------------------

    def events(
        self,
        *,
        event_type: str | None = None,
        pid: int | None = None,
        process_key: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        clauses, params = self._filters(
            event_type=("event_type", event_type),
            pid=("pid", pid),
            process_key=("process_key", process_key),
        )
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # `where` is built only from fixed column names in code; all values are parameterized.
        return self.db.query(
            f"SELECT * FROM security_events {where} ORDER BY timestamp DESC, id DESC LIMIT ?",  # noqa: S608
            [*params, limit],
        )

    def alerts(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        clauses, params = self._filters(severity=("severity", severity), status=("status", status))
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self.db.query(
            f"SELECT * FROM alerts {where} ORDER BY risk_score DESC, updated_at DESC LIMIT ?",  # noqa: S608
            [*params, limit],
        )

    def alert(self, alert_id: str) -> sqlite3.Row | None:
        return self.db.query_one(
            "SELECT * FROM alerts WHERE alert_id=? OR alert_id LIKE ?", (alert_id, f"{alert_id}%")
        )

    def detections_for(self, alert_id: str) -> list[sqlite3.Row]:
        return self.db.query(
            "SELECT * FROM detections WHERE alert_id=? ORDER BY score DESC", (alert_id,)
        )

    def actions(self, *, limit: int = 100) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?", (limit,))

    def counts(self) -> dict[str, int]:
        tables = (
            "security_events",
            "network_connections",
            "detections",
            "alerts",
            "actions",
            "processes",
            "persistence_items",
        )
        result: dict[str, int] = {}
        for table in tables:  # table names come from the fixed tuple above, never user input
            row = self.db.query_one(f"SELECT COUNT(*) c FROM {table}")  # noqa: S608
            result[table] = int(row["c"]) if row is not None else 0
        return result

    @staticmethod
    def _filters(**named: tuple[str, Any]) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in named.values():
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        return clauses, params


@dataclass(frozen=True, slots=True)
class DatabaseInfo:
    path: str
    version: int
    size_bytes: int
    counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class StoredAlert:
    """A read-only alert from the database (satisfies ``ui.alert_views.AlertLike``)."""

    alert_id: str
    severity: Severity
    risk_score: int
    confidence: Confidence
    status: AlertStatus
    process_key: str | None
    pid: int | None
    process_name: str | None
    exe: str | None
    created_at: datetime
    updated_at: datetime
    rules_triggered: tuple[str, ...]
    score_breakdown: tuple[ScoreContribution, ...]
    recommended_actions: tuple[str, ...]
    network: tuple[NetworkContext, ...]

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "process_key": self.process_key,
            "pid": self.pid,
            "process_name": self.process_name,
            "exe": self.exe,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "rules_triggered": list(self.rules_triggered),
            "score_breakdown": [c.model_dump(mode="json") for c in self.score_breakdown],
            "recommended_actions": list(self.recommended_actions),
            "network": [n.model_dump(mode="json") for n in self.network],
        }


def alert_from_row(row: sqlite3.Row) -> StoredAlert:
    return StoredAlert(
        alert_id=row["alert_id"],
        severity=Severity(row["severity"]),
        risk_score=row["risk_score"],
        confidence=Confidence(row["confidence"]),
        status=AlertStatus(row["status"]),
        process_key=row["process_key"],
        pid=row["pid"],
        process_name=row["process_name"],
        exe=row["exe"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        rules_triggered=tuple(loads(row["rules_triggered"])),
        score_breakdown=tuple(
            ScoreContribution.model_validate(c) for c in loads(row["score_breakdown"])
        ),
        recommended_actions=tuple(loads(row["recommended_actions"])),
        network=tuple(NetworkContext.model_validate(n) for n in loads(row["network"])),
    )
