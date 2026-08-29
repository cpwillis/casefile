"""SQLite response cache. Wraps run_fetcher from outside so the fetch contract stays storage-free.

The cache holds third-party data pulled from public sources, so clear_cache is a privacy
control as much as a debugging one.
"""

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from casefile import store
from casefile.fetchers import Finding, SourceResult, State, run_fetcher

ANSWERED = (State.OK, State.EMPTY)  # a source that actually replied, whether or not it had data
RETENTION_SECONDS = 86400.0
# A failure keeps for minutes, not a day: long enough that reloading a page does not re-hammer a
# source that just 502'd, short enough that a transient outage clears itself and a key you have
# just configured takes effect without --clear-cache.
FAILURE_RETENTION = 300.0
_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    source_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    payload     TEXT NOT NULL,
    PRIMARY KEY (source_id, entity_type, value)
);
"""


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "casefile" / "cache.db"


def _connect():
    conn = store.connect(cache_path(), _SCHEMA)
    # Swept on every open, not on write. Retention is a privacy claim, not housekeeping: a
    # session that fetches nothing cacheable (offline, every source erroring) would otherwise
    # leave yesterday's search terms and payloads on disk indefinitely.
    conn.execute("DELETE FROM responses WHERE fetched_at < ?", (time.time() - RETENTION_SECONDS,))
    return conn


def _ttl_for(state: str) -> float:
    return RETENTION_SECONDS if state in ANSWERED else FAILURE_RETENTION


def _load(source_id: str, entity_type, value: str, ttl: float | None = None) -> SourceResult | None:
    if not cache_path().exists():
        return None  # a miss must not bring the store into being; only storing a response does
    with _connect() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE source_id = ? AND entity_type = ? AND value = ?",
            (source_id, str(entity_type), value),
        ).fetchone()
    if row is None:
        return None
    data = json.loads(row[1])
    if time.time() - row[0] > (_ttl_for(data["state"]) if ttl is None else ttl):
        return None
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
    """Delete every cached response by removing the database file. Returns rows removed."""
    return store.purge(cache_path(), "responses")


def cached_result(source_id, entity_type, value) -> SourceResult | None:
    """A stored response if one is still fresh, making no request at all. Never raises.

    This is what lets an already-run panel paint on page load instead of round-tripping, and
    what lets an on-demand source stay on the page across reloads: consent is for the egress,
    and a cache hit spends none.
    """
    try:
        return _load(source_id, entity_type, value)
    except Exception:  # noqa: BLE001 -- a broken cache must never break a render
        return None


async def run_cached(
    source_id, value, entity_type, client, *, ttl: float | None = None, use_cache: bool = True, refresh: bool = False
):
    """run_fetcher with a SQLite read-through cache. Every outcome is stored, with a retention
    that depends on it: see FAILURE_RETENTION.

    The two ways to skip the stored answer are not the same and must not be merged: `use_cache`
    off means do not touch the cache at all (the CLI's --no-cache, a privacy control), while
    `refresh` means ignore what is stored but replace it with what comes back, which is what the
    per-panel refresh control needs. A refresh that did not write would be thrown away and the
    next page load would show the stale answer again.

    Cache failures are contained: a broken or unwritable cache degrades to an uncached lookup
    rather than failing the request, because a 500 leaves the panel loading forever.
    """
    if use_cache and not refresh:
        try:
            hit = _load(source_id, entity_type, value, ttl)
        except Exception:  # noqa: BLE001 -- a broken cache must never break a lookup
            hit = None
        if hit is not None:
            return hit
    result = await run_fetcher(source_id, value, entity_type, client)
    if use_cache:
        try:  # noqa: SIM105 -- explicit try/except reads clearer here than contextlib.suppress
            _store(result, entity_type, value)
        except Exception:  # noqa: BLE001 -- failing to cache is not failing to fetch
            pass
    return result
