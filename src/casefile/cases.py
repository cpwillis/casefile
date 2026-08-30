"""Saved cases: an investigation, the identifiers in it, and the findings starred against them.

One case spans several identifiers: `acme-example` the username and `acme.example` the domain are one case.
Lives under XDG_DATA_HOME, not XDG_CACHE_HOME: saved work is not disposable and `--clear-cache` must not touch it.
"""

import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from casefile import store
from casefile.types import EntityType


class CaseStoreError(Exception):
    """The cases store could not be written. Callers must surface this, never swallow it."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
    case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    added_at    REAL NOT NULL,
    PRIMARY KEY (case_id, entity_type, value)
);
CREATE TABLE IF NOT EXISTS stars (
    case_id      TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    target_type  TEXT NOT NULL,
    target_value TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    label        TEXT NOT NULL,
    value        TEXT NOT NULL,
    url          TEXT,
    starred_at   REAL NOT NULL,
    PRIMARY KEY (case_id, target_type, target_value, source_id, label, value)
);
-- An identifier belongs to at most one case, so "already saved?" is one indexed lookup from a target alone.
CREATE UNIQUE INDEX IF NOT EXISTS targets_unique ON targets (entity_type, value);
"""


@dataclass(frozen=True)
class Star:
    """One finding you chose to keep. Mirrors Finding, plus the source and target it came from."""

    source_id: str
    label: str
    value: str
    url: str | None = None
    target_type: str = ""
    target_value: str = ""
    starred_at: float = 0.0


@dataclass(frozen=True)
class Target:
    entity_type: str
    value: str
    added_at: float = 0.0
    star_count: int = 0


@dataclass(frozen=True)
class Case:
    id: str
    name: str
    created_at: float
    updated_at: float
    star_count: int = 0
    targets: tuple[Target, ...] = ()
    stars: tuple[Star, ...] = ()


def cases_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "casefile" / "cases.db"


def _connect() -> sqlite3.Connection:
    return store.connect(cases_path(), _SCHEMA)


def _read(default, query):
    """Run a read, returning `default` when there is no usable store. Browsing never creates one; only saving does."""
    if not cases_path().exists():
        return default
    try:
        with _connect() as conn:
            return query(conn)
    except (sqlite3.Error, OSError):
        return default


def _write(query):
    try:
        with _connect() as conn:
            return query(conn)
    except (sqlite3.Error, OSError) as exc:
        raise CaseStoreError(str(exc)) from exc


def _touch(conn, case_id: str) -> None:
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (time.time(), case_id))


def _drop_if_empty(conn, case_id: str) -> None:
    """Drop a case with no identifiers left. Losing its last star does not: that is one row, not the investigation."""
    if conn.execute("SELECT 1 FROM targets WHERE case_id = ? LIMIT 1", (case_id,)).fetchone() is None:
        conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))


def _case_of(conn, target: tuple[str, str]) -> str | None:
    row = conn.execute("SELECT case_id FROM targets WHERE entity_type = ? AND value = ?", target).fetchone()
    return None if row is None else row[0]


NAME_LIMIT = 120


def _new_case(conn, name: str, now: float) -> str:
    # Opaque, not derived from the first target: a case gets renamed and gains targets, so a derived id misleads.
    cid = secrets.token_hex(6)
    name = name[:NAME_LIMIT]  # bound at creation too, so a case auto-named after a long value can be renamed to it
    conn.execute("INSERT INTO cases (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", (cid, name, now, now))
    return cid


def case_for_target(entity_type: EntityType, value: str) -> Case | None:
    """The case this identifier belongs to, if any. Every result page asks, so: one indexed lookup, never raises."""

    def query(conn):
        cid = _case_of(conn, (str(entity_type), value))
        return None if cid is None else _load(conn, cid)

    return _read(None, query)


def save_target(entity_type: EntityType, value: str, case_id: str | None = None, name: str = "") -> str:
    """Add an identifier to a case, new one when case_id is None. Re-saving moves it, stars and all. Returns the id."""

    if not value.strip():
        raise CaseStoreError("an identifier cannot be blank")

    def query(conn):
        now = time.time()
        target = (str(entity_type), value)
        held_by = _case_of(conn, target)
        cid = case_id
        if cid is None:
            if held_by:
                return held_by
            cid = _new_case(conn, name.strip() or value, now)
        elif conn.execute("SELECT 1 FROM cases WHERE id = ?", (cid,)).fetchone() is None:
            raise sqlite3.IntegrityError(f"no such case {cid}")
        if held_by and held_by != cid:
            conn.execute("UPDATE stars SET case_id = ? WHERE target_type = ? AND target_value = ?", (cid, *target))
            conn.execute("DELETE FROM targets WHERE entity_type = ? AND value = ?", target)
            _touch(conn, held_by)
            _drop_if_empty(conn, held_by)
        conn.execute(
            "INSERT OR IGNORE INTO targets (case_id, entity_type, value, added_at) VALUES (?, ?, ?, ?)",
            (cid, *target, now),
        )
        _touch(conn, cid)
        return cid

    return _write(query)


def remove_target(entity_type: EntityType, value: str) -> None:
    """Take one identifier, and its findings, out of whatever case holds it."""

    def query(conn):
        target = (str(entity_type), value)
        cid = _case_of(conn, target)
        if cid is None:
            return
        conn.execute("DELETE FROM stars WHERE target_type = ? AND target_value = ?", target)
        conn.execute("DELETE FROM targets WHERE entity_type = ? AND value = ?", target)
        _touch(conn, cid)
        _drop_if_empty(conn, cid)

    _write(query)


def rename_case(case_id: str, name: str) -> None:
    """Rename a case. Bounded: unbounded, a name stretched the "add to" select past 4000px on every result page."""
    name = name.strip()
    if not name:
        raise CaseStoreError("a case needs a name")
    if len(name) > NAME_LIMIT:
        raise CaseStoreError(f"a case name is at most {NAME_LIMIT} characters, that one is {len(name)}")
    _write(
        lambda conn: conn.execute(
            "UPDATE cases SET name = ?, updated_at = ? WHERE id = ?", (name, time.time(), case_id)
        )
    )


def star(entity_type: EntityType, value: str, finding: Star) -> str:
    """Keep one finding, saving the target first if it was not saved. Returns the case id."""

    def query(conn):
        now = time.time()
        target = (str(entity_type), value)
        cid = _case_of(conn, target)
        if cid is None:
            cid = _new_case(conn, value, now)
            conn.execute(
                "INSERT INTO targets (case_id, entity_type, value, added_at) VALUES (?, ?, ?, ?)", (cid, *target, now)
            )
        conn.execute(
            "INSERT OR IGNORE INTO stars "
            "(case_id, target_type, target_value, source_id, label, value, url, starred_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (cid, *target, finding.source_id, finding.label, finding.value, finding.url, now),
        )
        _touch(conn, cid)
        return cid

    return _write(query)


def unstar(entity_type: EntityType, value: str, finding: Star) -> None:
    """Drop one finding. Unlike remove_target, the case and target stay even if this was the last star."""

    def query(conn):
        target = (str(entity_type), value)
        cid = _case_of(conn, target)
        if cid is None:
            return
        conn.execute(
            "DELETE FROM stars WHERE target_type = ? AND target_value = ? "
            "AND source_id = ? AND label = ? AND value = ?",
            (*target, finding.source_id, finding.label, finding.value),
        )
        _touch(conn, cid)

    _write(query)


def starred_keys(entity_type: EntityType, value: str) -> frozenset[tuple[str, str, str]]:
    """Every starred (source, label, value) for one target in one query: per row was a connection per finding."""
    return _read(
        frozenset(),
        lambda conn: frozenset(
            conn.execute(
                "SELECT source_id, label, value FROM stars WHERE target_type = ? AND target_value = ?",
                (str(entity_type), value),
            ).fetchall()
        ),
    )


def _load(conn, case_id: str) -> Case | None:
    row = conn.execute("SELECT id, name, created_at, updated_at FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        return None
    per_target = dict(
        conn.execute(
            "SELECT target_type || ' ' || target_value, COUNT(*) FROM stars WHERE case_id = ? GROUP BY 1", (case_id,)
        ).fetchall()
    )
    targets = tuple(
        Target(entity_type=t[0], value=t[1], added_at=t[2], star_count=per_target.get(f"{t[0]} {t[1]}", 0))
        for t in conn.execute(
            "SELECT entity_type, value, added_at FROM targets WHERE case_id = ? ORDER BY added_at, value", (case_id,)
        ).fetchall()
    )
    stars = tuple(
        Star(source_id=s[0], label=s[1], value=s[2], url=s[3], target_type=s[4], target_value=s[5], starred_at=s[6])
        for s in conn.execute(
            "SELECT source_id, label, value, url, target_type, target_value, starred_at FROM stars WHERE case_id = ? "
            "ORDER BY target_type, target_value, source_id, label, value",
            (case_id,),
        ).fetchall()
    )
    return Case(row[0], row[1], row[2], row[3], star_count=len(stars), targets=targets, stars=stars)


def load_case(case_id: str) -> Case | None:
    """A corrupt store reads as "no such case" rather than a 500."""
    return _read(None, lambda conn: _load(conn, case_id))


def list_cases() -> tuple[Case, ...]:
    def query(conn):
        ids = [r[0] for r in conn.execute("SELECT id FROM cases ORDER BY updated_at DESC, id").fetchall()]
        return tuple(case for cid in ids if (case := _load(conn, cid)) is not None)

    return _read((), query)


def forget_all() -> int:
    return store.purge(cases_path(), "cases")


def delete_case(case_id: str) -> bool:
    """Remove one case. Its targets and stars go with it: foreign keys are on and both cascade. A store failure
    raises rather than reading as False, so a delete that could not happen is not reported as already gone."""
    return _write(lambda conn: conn.execute("DELETE FROM cases WHERE id = ?", (case_id,)).rowcount > 0)
