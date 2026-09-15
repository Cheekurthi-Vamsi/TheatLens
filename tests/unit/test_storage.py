from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from fixtures.fakes import minutes
from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    Evidence,
    RuleCategory,
    SecurityEvent,
)
from winsentinel.detection.alerting import build_alert
from winsentinel.storage.database import Database
from winsentinel.storage.migrations import LATEST_VERSION
from winsentinel.storage.repositories import SecurityStore, alert_from_row
from winsentinel.storage.writer import DatabaseWriter


@pytest.fixture
def store(tmp_path: Path) -> SecurityStore:
    return SecurityStore(Database.open(tmp_path / "test.db"))


def event(event_type: EventType, **data: object) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        source="test",
        timestamp=minutes(1),
        process_key=str(data.pop("process_key", "20:0")),
        pid=20,
        data=data,
    )


def detection(rule_id: str = "PROC-005", score: int = 45) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name="masquerade",
        category=RuleCategory.MASQUERADE,
        score=score,
        confidence=Confidence.HIGH,
        summary="svchost.exe suspicious",
        evidence=(Evidence(description="named like a system binary"),),
        process_key="20:0",
        pid=20,
        process_name="svchost.exe",
        exe=r"C:\Temp\svchost.exe",
    )


class TestMigrations:
    def test_fresh_database_is_at_latest_version(self, tmp_path: Path) -> None:
        with Database.open(tmp_path / "a.db") as db:
            assert db.version() == LATEST_VERSION

    def test_migrations_are_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / "b.db"
        Database.open(path).close()
        with Database.open(path) as db:  # re-open applies nothing new
            assert db.version() == LATEST_VERSION
            tables = {
                r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert {"processes", "security_events", "alerts", "detections", "actions"} <= tables


class TestSideEffects:
    def test_process_lifecycle_updates_row(self, store: SecurityStore) -> None:
        store.record_event(
            event(EventType.PROCESS_STARTED, name="app.exe", exe=r"C:\app.exe", ppid=4)
        )
        store.record_event(
            event(
                EventType.PROCESS_ENRICHED,
                name="app.exe",
                sha256="ab" * 32,
                signature_status="VALID",
                signer="ACME",
            )
        )
        store.record_event(
            event(EventType.PROCESS_STOPPED, name="app.exe", exited_before=minutes(2).isoformat())
        )
        row = store.db.query_one("SELECT * FROM processes WHERE process_key='20:0'")
        assert row is not None
        assert row["name"] == "app.exe" and row["sha256"] == "ab" * 32
        assert row["signature_status"] == "VALID" and row["exited_at"] is not None

    def test_event_is_recorded_once(self, store: SecurityStore) -> None:
        e = event(EventType.PROCESS_STARTED, name="app.exe")
        store.record_event(e)
        store.record_event(e)  # same event_id
        assert store.db.query_one("SELECT COUNT(*) c FROM security_events")["c"] == 1

    def test_connection_upsert_keys_on_connection_key(self, store: SecurityStore) -> None:
        data = {
            "connection_key": "TCP|10.0.0.5|5|-|0|20|1",
            "protocol": "TCP",
            "family": "IPV4",
            "local_address": "10.0.0.5",
            "local_port": 5,
            "state": "SYN_SENT",
            "direction": "OUTBOUND",
        }
        store.record_event(
            SecurityEvent(
                event_type=EventType.CONNECTION_OPENED,
                source="t",
                timestamp=minutes(1),
                pid=20,
                data=data,
            )
        )
        store.record_event(
            SecurityEvent(
                event_type=EventType.CONNECTION_CLOSED,
                source="t",
                timestamp=minutes(2),
                pid=20,
                data={**data, "state": "CLOSE_WAIT"},
            )
        )
        rows = store.db.query("SELECT * FROM network_connections")
        assert (
            len(rows) == 1 and rows[0]["state"] == "CLOSE_WAIT" and rows[0]["closed_at"] is not None
        )


class TestAlerts:
    def test_alert_roundtrip_and_stored_view(self, store: SecurityStore) -> None:
        det = detection()
        alert = build_alert("20:0", [det], running=True)
        assert alert is not None
        store.record_detection(det)
        store.upsert_alert(alert)
        row = store.alert(alert.alert_id[:8])
        assert row is not None
        stored = alert_from_row(row)
        assert stored.risk_score == alert.risk_score
        assert stored.severity == alert.severity
        assert stored.rules_triggered == ("PROC-005",)
        assert len(stored.score_breakdown) == 1
        # The detection is now linked to the alert.
        assert store.detections_for(alert.alert_id)[0]["rule_id"] == "PROC-005"

    def test_user_status_survives_reobservation(self, store: SecurityStore) -> None:
        det = detection()
        alert = build_alert("20:0", [det], running=True)
        assert alert is not None
        store.upsert_alert(alert)
        store.set_alert_status(alert.alert_id, "RESOLVED")
        # A later engine run re-upserts the same alert (status NEW) — must not reopen it.
        store.upsert_alert(alert)
        row = store.alert(alert.alert_id)
        assert row is not None and row["status"] == "RESOLVED"

    def test_set_status_accepts_prefix(self, store: SecurityStore) -> None:
        alert = build_alert("20:0", [detection()], running=True)
        assert alert is not None
        store.upsert_alert(alert)
        assert store.set_alert_status(alert.alert_id[:8], "ACKNOWLEDGED") is True
        assert store.set_alert_status("deadbeef", "IGNORED") is False


class TestRetention:
    def test_old_events_deleted_but_linked_detections_kept(self, store: SecurityStore) -> None:
        store.record_event(event(EventType.PROCESS_STARTED, name="old.exe"))
        det = detection()
        alert = build_alert("20:0", [det], running=True)
        assert alert is not None
        store.record_detection(det)
        store.upsert_alert(alert)  # links the detection
        store.db.commit()
        deleted = store.apply_retention(
            event_days=7, alert_days=90, action_days=0, now=minutes(1) + timedelta(days=30)
        )
        assert deleted.get("security_events", 0) == 1
        # The detection is linked to an alert, so it is retained.
        assert store.db.query_one("SELECT COUNT(*) c FROM detections")["c"] == 1

    def test_resolved_alerts_expire(self, store: SecurityStore) -> None:
        alert = build_alert("20:0", [detection()], running=True)
        assert alert is not None
        store.upsert_alert(alert)
        store.set_alert_status(alert.alert_id, "RESOLVED")
        deleted = store.apply_retention(
            0, alert_days=30, action_days=0, now=alert.updated_at + timedelta(days=31)
        )
        assert deleted.get("alerts") == 1


class TestWriter:
    def test_batched_writes_flush_and_survive_shutdown(self, tmp_path: Path) -> None:
        path = tmp_path / "w.db"
        writer = DatabaseWriter(path)
        writer.start()
        for i in range(50):
            writer.on_event(
                event(EventType.PROCESS_STARTED, name=f"p{i}.exe", process_key=f"{i}:0")
            )
        writer.on_detection(detection())
        alert = build_alert("20:0", [detection()], running=True)
        assert alert is not None
        writer.on_alert(alert)
        assert writer.stop(timeout=5.0) is True
        with Database(path) as db:
            store = SecurityStore(db)
            counts = store.counts()
        assert counts["security_events"] == 50
        assert counts["alerts"] == 1
        assert writer.stats().dropped == 0

    def test_config_history_deduplicates(self, store: SecurityStore) -> None:
        store.record_config("cfg.toml", "a = 1")
        store.record_config("cfg.toml", "a = 1")
        store.record_config("cfg.toml", "a = 2")
        assert store.db.query_one("SELECT COUNT(*) c FROM configuration_history")["c"] == 2
