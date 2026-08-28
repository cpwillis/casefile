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
_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    source_id  TEXT NOT NULL,
    value      TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (source_id, value)
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
    return conn


def _load(source_id: str, value: str, ttl: float) -> SourceResult | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE source_id = ? AND value = ?",
            (source_id, value),
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


def _store(result: SourceResult, value: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO responses (source_id, value, fetched_at, payload) VALUES (?, ?, ?, ?)",
            (result.source_id, value, time.time(), json.dumps(asdict(result))),
        )


def clear_cache() -> int:
    """Delete every cached response. Returns the number of rows removed."""
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM responses")
        return cursor.rowcount if cursor.rowcount > 0 else 0


async def run_cached(source_id, value, entity_type, client, *, ttl: float = 86400, use_cache: bool = True):
    """run_fetcher with a SQLite read-through cache. Only ok and empty are stored."""
    if use_cache and (hit := _load(source_id, value, ttl)) is not None:
        return hit
    result = await run_fetcher(source_id, value, entity_type, client)
    if use_cache and result.state in CACHEABLE:
        _store(result, value)
    return result
