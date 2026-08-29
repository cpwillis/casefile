"""Sqlite plumbing shared by the response cache and the saved-cases store.

Its own module rather than one store importing the other: the durable store must not depend on
the disposable one. Both stores document their purge as a privacy control, and that rule is
subtle enough that having it written twice was an invitation to fix one copy and miss the other.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

_SIDECARS = ("-journal", "-wal", "-shm")


def connect(path: Path, schema: str, migrate=None) -> sqlite3.Connection:
    """Open a store, creating its directory and schema if this is the first use.

    `migrate` runs before the schema script and before foreign keys are switched on, which is
    the order a table rebuild needs. It matters because CREATE TABLE IF NOT EXISTS is silent
    when a table of that name already exists with different columns: without a migration hook,
    an older store does not fail to open, it fails on the first write with a missing column.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    if migrate is not None:
        migrate(conn)
    conn.execute("PRAGMA foreign_keys = ON")  # off by default, and cases' cascade depends on it
    conn.executescript(schema)
    return conn


def purge(path: Path, table: str) -> int:
    """Delete a whole store by removing its file. Returns how many rows of `table` went.

    Removing the file rather than running DELETE: sqlite frees pages without zeroing them, so
    after a DELETE the search terms and third-party payloads stay byte-readable in the file.
    Both callers advertise this as a privacy control, so it has to actually remove the data.
    The rollback journal and any wal/shm siblings hold pre-image pages, so they go too.
    """
    if not path.exists():
        return 0
    # A bare connect, not `connect`: no point writing a schema into a file about to go. Closed
    # explicitly, because sqlite3's context manager commits without closing and the next line
    # unlinks the file the handle is still holding.
    try:
        with closing(sqlite3.connect(path)) as conn:
            count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608
    except sqlite3.Error:  # unreadable or corrupt, which is still something to remove
        count = 0
    path.unlink(missing_ok=True)
    for suffix in _SIDECARS:
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return count
