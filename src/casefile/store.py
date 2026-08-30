"""Sqlite plumbing shared by the disposable response cache and the durable cases store, so neither imports the other."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path

_SIDECARS = ("-journal", "-wal", "-shm")


def connect(path: Path, schema: str) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Owner-only: a store of someone's searches and third-party payloads must not be world-readable. Dir 0700
    # covers the journal/wal/shm sidecars too, so they need no separate chmod.
    os.chmod(path.parent, 0o700)
    conn = sqlite3.connect(path)
    os.chmod(path, 0o600)
    conn.execute("PRAGMA foreign_keys = ON")  # off by default, and cases' cascade depends on it
    conn.executescript(schema)
    return conn


def purge(path: Path, table: str) -> int:
    """Delete a store by unlinking its file, plus the journal/wal/shm siblings holding pre-image pages. Returns rows.

    DELETE is not enough: sqlite frees pages without zeroing, leaving search terms readable in the file.
    """
    if not path.exists():
        return 0
    # Bare connect, no schema into a doomed file. Closed explicitly: sqlite3's CM commits but never closes the handle.
    try:
        with closing(sqlite3.connect(path)) as conn:
            count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608
    except sqlite3.Error:  # unreadable or corrupt, which is still something to remove
        count = 0
    path.unlink(missing_ok=True)
    for suffix in _SIDECARS:
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return count
