"""SQLite response cache. Wraps run_fetcher from outside so the fetch contract stays storage-free.

The cache holds third-party data pulled from public sources, so clear_cache is a privacy
control as much as a debugging one.
"""

import json
import os
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from casefile.fetchers import Finding, SourceResult, State, run_fetcher

CACHEABLE = (State.OK, State.EMPTY)
RETENTION_SECONDS = 86400.0
_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    source_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    payload     TEXT NOT NULL,
    PRIMARY KEY (source_id, entity_type, value)
)
"""


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "casefile" / "cache.db"


def _connect() -> sqlite3.Connection:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    conn.execute("DELETE FROM responses WHERE fetched_at < ?", (time.time() - RETENTION_SECONDS,))
    return conn


def _load(source_id: str, entity_type, value: str, ttl: float) -> SourceResult | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE source_id = ? AND entity_type = ? AND value = ?",
            (source_id, str(entity_type), value),
        ).fetchone()
    if row is None or time.time() - row[0] > ttl:
        return None
    data = json.loads(row[1])
    findings = tuple(Finding(**f) for f in data.get("findings", []))
    return SourceResult(
        source_id=data["source_id"],
        state=data["state"],
        findings=findings,
        detail=data.get("detail"),
        elapsed_ms=data.get("elapsed_ms", 0),
    )


def _store(result: SourceResult, entity_type, value: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO responses (source_id, entity_type, value, fetched_at, payload) "
            "VALUES (?, ?, ?, ?, ?)",
            (result.source_id, str(entity_type), value, time.time(), json.dumps(asdict(result))),
        )


def clear_cache() -> int:
    """Delete every cached response by removing the database file. Returns rows removed.

    Unlinking rather than running DELETE matters: sqlite frees pages without zeroing them, so
    after a DELETE the search terms and third-party payloads stayed byte-readable in the file.
    This is documented as a privacy control, so it has to actually remove the data.
    """
    path = cache_path()
    if not path.exists():
        return 0
    try:
        with _connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0])
    except sqlite3.Error:
        count = 0
    path.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return count


async def run_cached(source_id, value, entity_type, client, *, ttl: float = 86400, use_cache: bool = True):
    """run_fetcher with a SQLite read-through cache. Only ok and empty are stored.

    Cache failures are contained: a broken or unwritable cache degrades to an uncached lookup
    rather than failing the request, because a 500 leaves the panel loading forever.
    """
    if use_cache:
        try:
            hit = _load(source_id, entity_type, value, ttl)
        except Exception:  # noqa: BLE001 -- a broken cache must never break a lookup
            hit = None
        if hit is not None:
            return hit
    result = await run_fetcher(source_id, value, entity_type, client)
    if use_cache and result.state in CACHEABLE:
        try:  # noqa: SIM105 -- explicit try/except reads clearer here than contextlib.suppress
            _store(result, entity_type, value)
        except Exception:  # noqa: BLE001 -- failing to cache is not failing to fetch
            pass
    return result
