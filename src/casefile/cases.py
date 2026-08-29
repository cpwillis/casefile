"""Saved cases: the findings you deliberately starred, kept between runs.

This is the only place casefile records what you searched, and it records it only when you ask.
It lives under XDG_DATA_HOME rather than XDG_CACHE_HOME because it is not disposable: the
response cache can be thrown away at any time, your saved work cannot. `--clear-cache` must
never touch this file.
"""

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from casefile.types import EntityType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS stars (
    case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_id  TEXT NOT NULL,
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    url        TEXT,
    starred_at REAL NOT NULL,
    PRIMARY KEY (case_id, source_id, label, value)
);
"""


@dataclass(frozen=True)
class Star:
    """One finding you chose to keep. Mirrors Finding, but persisted and source-attributed."""

    source_id: str
    label: str
    value: str
    url: str | None = None


@dataclass(frozen=True)
class Case:
    id: str
    entity_type: str
    value: str
    created_at: float
    updated_at: float
    star_count: int = 0
    stars: tuple[Star, ...] = ()


def cases_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "casefile" / "cases.db"


def case_id_for(entity_type: EntityType, value: str) -> str:
    """Derived, not random, so the same target always reopens the same case."""
    return f"{entity_type}:{value}"


def _connect() -> sqlite3.Connection:
    path = cases_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")  # off by default, and the cascade depends on it
    conn.executescript(_SCHEMA)
    return conn


def star(entity_type: EntityType, value: str, finding: Star) -> str:
    """Keep one finding. Creates the case if this is the first star. Returns the case id."""
    case_id = case_id_for(entity_type, value)
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (id, entity_type, value, created_at, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at",
            (case_id, str(entity_type), value, now, now),
        )
        conn.execute(
            "INSERT OR IGNORE INTO stars (case_id, source_id, label, value, url, starred_at) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, finding.source_id, finding.label, finding.value, finding.url, now),
        )
    return case_id


def unstar(entity_type: EntityType, value: str, finding: Star) -> None:
    """Drop one finding, and the case with it if that was the last one."""
    case_id = case_id_for(entity_type, value)
    with _connect() as conn:
        conn.execute(
            "DELETE FROM stars WHERE case_id = ? AND source_id = ? AND label = ? AND value = ?",
            (case_id, finding.source_id, finding.label, finding.value),
        )
        remaining = conn.execute("SELECT COUNT(*) FROM stars WHERE case_id = ?", (case_id,)).fetchone()[0]
        if remaining:
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (time.time(), case_id))
        else:
            conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))


def is_starred(entity_type: EntityType, value: str, finding: Star) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM stars WHERE case_id = ? AND source_id = ? AND label = ? AND value = ?",
            (case_id_for(entity_type, value), finding.source_id, finding.label, finding.value),
        ).fetchone()
    return row is not None


def list_cases() -> tuple[Case, ...]:
    """Every saved case, most recently updated first. Counts stars but does not load them."""
    if not cases_path().exists():
        return ()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT c.id, c.entity_type, c.value, c.created_at, c.updated_at, COUNT(s.case_id) "
            "FROM cases c LEFT JOIN stars s ON s.case_id = c.id "
            "GROUP BY c.id ORDER BY c.updated_at DESC, c.id"
        ).fetchall()
    return tuple(
        Case(id=r[0], entity_type=r[1], value=r[2], created_at=r[3], updated_at=r[4], star_count=r[5]) for r in rows
    )


def load_case(case_id: str) -> Case | None:
    if not cases_path().exists():
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, entity_type, value, created_at, updated_at FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            return None
        stars = conn.execute(
            "SELECT source_id, label, value, url FROM stars WHERE case_id = ? ORDER BY source_id, label, value",
            (case_id,),
        ).fetchall()
    kept = tuple(Star(source_id=s[0], label=s[1], value=s[2], url=s[3]) for s in stars)
    return Case(
        id=row[0],
        entity_type=row[1],
        value=row[2],
        created_at=row[3],
        updated_at=row[4],
        star_count=len(kept),
        stars=kept,
    )


def forget_all() -> int:
    """Delete every saved case by removing the file. Returns how many cases went.

    Removing the file rather than running DELETE, for the same reason the cache does: sqlite
    frees pages without zeroing them, so a DELETE would leave the values readable on disk.
    """
    path = cases_path()
    if not path.exists():
        return 0
    try:
        with _connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0])
    except sqlite3.Error:
        count = 0
    path.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return count
