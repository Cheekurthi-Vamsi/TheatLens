"""Numbered, forward-only schema migrations (docs/architecture.md §12).

Each migration is a ``(version, description, statements)`` tuple applied inside one transaction
and recorded in ``schema_migrations``. All V1 tables are created in migration 1 so later phases
consume them without new migrations; when a future change is needed, add migration 2 rather than
editing migration 1.

Conventions: timestamps are ISO-8601 UTC ``TEXT`` (lexicographically sortable); JSON columns are
``TEXT``; every write uses parameterized queries (never string interpolation).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from winsentinel.utils.time import utc_now


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    description: str
    statements: Sequence[str]


_V1: Final = (
    """
    CREATE TABLE processes (
        process_key TEXT PRIMARY KEY, pid INTEGER NOT NULL, ppid INTEGER, parent_key TEXT,
        name TEXT NOT NULL, exe TEXT, cmdline TEXT, username TEXT, create_time TEXT,
        integrity_level TEXT, session_id INTEGER, architecture TEXT,
        sha256 TEXT, signature_status TEXT, signer TEXT,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, exited_at TEXT
    )
    """,
    "CREATE INDEX ix_processes_pid ON processes(pid)",
    "CREATE INDEX ix_processes_name ON processes(name)",
    "CREATE INDEX ix_processes_sha256 ON processes(sha256)",
    "CREATE INDEX ix_processes_first_seen ON processes(first_seen)",
    """
    CREATE TABLE security_events (
        id INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, schema_version INTEGER NOT NULL,
        event_type TEXT NOT NULL, timestamp TEXT NOT NULL, source TEXT NOT NULL,
        observation TEXT NOT NULL, process_key TEXT, pid INTEGER, data TEXT NOT NULL
    )
    """,
    "CREATE INDEX ix_sec_events_ts ON security_events(timestamp)",
    "CREATE INDEX ix_sec_events_type ON security_events(event_type, timestamp)",
    "CREATE INDEX ix_sec_events_pid ON security_events(pid)",
    "CREATE INDEX ix_sec_events_key ON security_events(process_key)",
    """
    CREATE TABLE network_connections (
        id INTEGER PRIMARY KEY, connection_key TEXT NOT NULL UNIQUE, process_key TEXT, pid INTEGER,
        protocol TEXT NOT NULL, family TEXT NOT NULL, local_address TEXT NOT NULL,
        local_port INTEGER NOT NULL, remote_address TEXT, remote_port INTEGER, state TEXT NOT NULL,
        direction TEXT NOT NULL, remote_scope TEXT, owner_module TEXT, created_at TEXT,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, closed_at TEXT
    )
    """,
    "CREATE INDEX ix_net_first_seen ON network_connections(first_seen)",
    "CREATE INDEX ix_net_pid ON network_connections(pid)",
    "CREATE INDEX ix_net_remote ON network_connections(remote_address)",
    "CREATE INDEX ix_net_key ON network_connections(process_key)",
    """
    CREATE TABLE detections (
        id INTEGER PRIMARY KEY, detection_id TEXT NOT NULL UNIQUE, alert_id TEXT,
        rule_id TEXT NOT NULL, timestamp TEXT NOT NULL, process_key TEXT, pid INTEGER,
        process_name TEXT, exe TEXT, score INTEGER NOT NULL, confidence TEXT NOT NULL,
        category TEXT NOT NULL, summary TEXT NOT NULL, evidence TEXT NOT NULL,
        network TEXT NOT NULL, mitre TEXT NOT NULL, event_ids TEXT NOT NULL
    )
    """,
    "CREATE INDEX ix_detections_ts ON detections(timestamp)",
    "CREATE INDEX ix_detections_rule ON detections(rule_id)",
    "CREATE INDEX ix_detections_key ON detections(process_key)",
    """
    CREATE TABLE alerts (
        alert_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
        risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100), status TEXT NOT NULL,
        process_key TEXT, pid INTEGER, process_name TEXT, exe TEXT,
        network TEXT NOT NULL, score_breakdown TEXT NOT NULL, rules_triggered TEXT NOT NULL,
        recommended_actions TEXT NOT NULL, detections TEXT NOT NULL
    )
    """,
    "CREATE INDEX ix_alerts_created ON alerts(created_at)",
    "CREATE INDEX ix_alerts_severity ON alerts(severity, created_at)",
    "CREATE INDEX ix_alerts_status ON alerts(status)",
    "CREATE INDEX ix_alerts_pid ON alerts(pid)",
    """
    CREATE TABLE persistence_items (
        id INTEGER PRIMARY KEY, item_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
        location TEXT NOT NULL, name TEXT NOT NULL, command TEXT, executable TEXT,
        arguments TEXT, sha256 TEXT, signature_status TEXT, signer TEXT,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, removed_at TEXT
    )
    """,
    "CREATE INDEX ix_persist_kind ON persistence_items(kind)",
    """
    CREATE TABLE actions (
        action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action_type TEXT NOT NULL,
        target TEXT NOT NULL, process_key TEXT, pid INTEGER, reason TEXT NOT NULL,
        requested_by TEXT NOT NULL, outcome TEXT NOT NULL, error TEXT,
        reverses_action_id TEXT, details TEXT NOT NULL
    )
    """,
    "CREATE INDEX ix_actions_ts ON actions(timestamp)",
    "CREATE INDEX ix_actions_type ON actions(action_type)",
    """
    CREATE TABLE firewall_rules (
        rule_name TEXT PRIMARY KEY, action_id TEXT NOT NULL, target_type TEXT NOT NULL,
        target TEXT NOT NULL, direction TEXT NOT NULL, created_at TEXT NOT NULL, removed_at TEXT
    )
    """,
    """
    CREATE TABLE baselines (
        baseline_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
        expires_at TEXT, created_by TEXT NOT NULL, hostname TEXT NOT NULL, notes TEXT,
        item_count INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE baseline_items (
        id INTEGER PRIMARY KEY,
        baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
        kind TEXT NOT NULL, item_key TEXT NOT NULL, label TEXT NOT NULL, attributes TEXT NOT NULL,
        UNIQUE (baseline_id, kind, item_key)
    )
    """,
    "CREATE INDEX ix_baseline_items ON baseline_items(baseline_id, kind)",
    """
    CREATE TABLE allowlist_entries (
        id INTEGER PRIMARY KEY, match_type TEXT NOT NULL
            CHECK (match_type IN ('EXE_PATH','SHA256','SIGNER')),
        value TEXT NOT NULL, rule_ids TEXT, reason TEXT NOT NULL, created_at TEXT NOT NULL,
        created_by TEXT NOT NULL, expires_at TEXT, UNIQUE (match_type, value)
    )
    """,
    """
    CREATE TABLE configuration_history (
        id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, config_sha256 TEXT NOT NULL,
        source_path TEXT NOT NULL, content TEXT NOT NULL
    )
    """,
)

MIGRATIONS: Final[tuple[Migration, ...]] = (Migration(1, "initial schema", _V1),)
LATEST_VERSION: Final = MIGRATIONS[-1].version


def current_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    result = connection.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
    ).fetchone()
    return int(result[0])


def apply_migrations(connection: sqlite3.Connection) -> int:
    """Apply every pending migration in order. Returns the resulting version."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    version = current_version(connection)
    for migration in MIGRATIONS:
        if migration.version <= version:
            continue
        with connection:  # one transaction per migration
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.description, utc_now().isoformat()),
            )
        version = migration.version
    return version
