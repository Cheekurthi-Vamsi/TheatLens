"""SQLite connection management.

* **WAL mode** so a reader (``winsentinel alerts`` in another terminal) never blocks the engine's
  writer and a crash cannot corrupt the database.
* ``foreign_keys=ON``, ``busy_timeout=5000``, ``synchronous=NORMAL`` (durable enough with WAL,
  much faster than FULL).
* One :class:`Database` wraps one connection. sqlite3 connections are not thread-safe, so the
  engine's writer thread owns its own; CLI read commands open their own read-only-ish connection.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from winsentinel.storage.migrations import LATEST_VERSION, apply_migrations, current_version


class Database:
    def __init__(self, path: Path | str, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self._read_only = read_only
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        uri = f"file:{self.path.as_posix()}?mode=ro" if read_only else None
        self._conn = sqlite3.connect(
            uri if uri else str(self.path),
            uri=uri is not None,
            check_same_thread=False,
            timeout=5.0,
        )
        self._conn.row_factory = sqlite3.Row
        if not read_only:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")

    @classmethod
    def open(cls, path: Path | str) -> Database:
        """Open (creating if needed) and migrate to the latest schema."""
        db = cls(path)
        db.migrate()
        return db

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def migrate(self) -> int:
        return apply_migrations(self._conn)

    def version(self) -> int:
        return current_version(self._conn)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        self._conn.executemany(sql, rows)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
        return row

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._conn:
            yield self._conn

    def commit(self) -> None:
        self._conn.commit()

    def vacuum(self) -> None:
        self._conn.execute("VACUUM")

    def checkpoint(self) -> None:
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        try:
            self._conn.commit()
        finally:
            self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def dumps(value: Any) -> str:
    """JSON for a TEXT column: compact, ASCII, deterministic."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), default=str)


def loads(value: str | None) -> Any:
    return None if value is None else json.loads(value)


def is_expected_schema(path: Path) -> bool:
    if not path.exists():
        return True
    with Database(path, read_only=True) as db:
        return db.version() == LATEST_VERSION
