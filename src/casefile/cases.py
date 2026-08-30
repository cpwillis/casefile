"""Saved cases: an investigation, the identifiers in it, and the findings starred against them.

A case is not a target. One investigation routinely spans several identifiers that are the same
subject to you and nothing alike to a detector, so `acme-example` the username and `acme.example`
the domain belong in one case rather than as two rows that merely look similar.

This is the only place casefile records what you searched, and it records it only when you ask.
It lives under XDG_DATA_HOME rather than XDG_CACHE_HOME because it is not disposable: the
response cache can be thrown away at any time, your saved work cannot. `--clear-cache` must
never touch this file.

Read paths never raise, because they sit on the hot path of a search that never depended on
them. Write paths do raise, because silently failing to save is worse than saying the save
failed.
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
-- An identifier belongs to at most one case, which is what makes "is this search already saved?"
-- a single indexed lookup from a page that only knows the target.
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
    """Run a read, or hand back `default` if there is no usable store.

    Both halves of the read policy live here so a reader added later cannot omit one: browsing
    never brings the store into being (only saving does), and a missing or corrupt store reads
    as "nothing saved" rather than breaking a search that never depended on it.
    """
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
    """A case with no identifiers left has nothing to be about, so it goes rather than sitting on
    the dashboard as a husk. Losing its last *star* does not do this: that is a change of mind
    about one row, not the end of the investigation."""
    if conn.execute("SELECT 1 FROM targets WHERE case_id = ? LIMIT 1", (case_id,)).fetchone() is None:
        conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))


def _case_of(conn, target: tuple[str, str]) -> str | None:
    row = conn.execute("SELECT case_id FROM targets WHERE entity_type = ? AND value = ?", target).fetchone()
    return None if row is None else row[0]


def _new_case(conn, name: str, now: float) -> str:
    # An opaque id, not a derived one. A case outlives the target it started from: it gets
    # renamed and gains targets, so anything derived from the first one goes stale or misleads.
    cid = secrets.token_hex(6)
    conn.execute("INSERT INTO cases (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", (cid, name, now, now))
    return cid


def case_for_target(entity_type: EntityType, value: str) -> Case | None:
    """The case this identifier already belongs to, if any. Never raises.

    Every result page asks this, so it is one indexed lookup and it has to be safe.
    """

    def query(conn):
        cid = _case_of(conn, (str(entity_type), value))
        return None if cid is None else _load(conn, cid)

    return _read(None, query)


def save_target(entity_type: EntityType, value: str, case_id: str | None = None, name: str = "") -> str:
    """Put an identifier in a case, creating the case when `case_id` is None. Returns the case id.

    This is what both "save this search" and "add this search to that case" call. Saving a target
    that is already saved moves it, findings and all, so joining two searches is one call rather
    than a remove and an add that could half-fail between them.
    """

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


NAME_LIMIT = 120


def rename_case(case_id: str, name: str) -> None:
    """A name is a label, not a document. Unbounded, it reached the "add to" select on every
    result page and stretched the layout past four thousand pixels."""
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
    """Keep one finding, saving the target first if it was not saved. Returns the case id.

    Starring alone is still enough to start a case, so the quick path stays one click.
    """

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
    """Drop one finding. The case and the target stay: a case you saved on purpose does not
    vanish because you changed your mind about one row."""

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
    """Every starred (source, label, value) for one target, in a single query.

    A panel asks once and answers for all of its rows. Asking per row was one sqlite connection
    per finding, which is linear in a number no source is obliged to keep small.
    """
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
    """Every saved case, most recently updated first, each with its targets."""

    def query(conn):
        ids = [r[0] for r in conn.execute("SELECT id FROM cases ORDER BY updated_at DESC, id").fetchall()]
        return tuple(case for cid in ids if (case := _load(conn, cid)) is not None)

    return _read((), query)


def forget_all() -> int:
    """Delete every saved case by removing the file. Returns how many cases went."""
    return store.purge(cases_path(), "cases")


def delete_case(case_id: str) -> bool:
    """Remove one case. Its targets and stars go with it: foreign keys are on and both cascade."""
    return _read(False, lambda conn: conn.execute("DELETE FROM cases WHERE id = ?", (case_id,)).rowcount > 0)
