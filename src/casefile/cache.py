"""SQLite response cache. Holds third-party data, so clear_cache is a privacy control as much as a debugging one."""

import asyncio
import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from casefile import store
from casefile.fetchers import Finding, SourceResult, State, run_fetcher

ANSWERED = (State.OK, State.EMPTY)  # a source that actually replied, whether or not it had data
RETENTION_SECONDS = 86400.0
# Minutes, not a day: long enough not to re-hammer a source that just 502'd, short enough that a new key takes effect.
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
CREATE INDEX IF NOT EXISTS responses_fetched_at ON responses (fetched_at);  -- the sweep on open scanned every row
"""


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if not base or not os.path.isabs(base):  # XDG spec: a relative path is ignored, or the store scatters by cwd
        base = Path.home() / ".cache"
    return Path(base) / "casefile" / "cache.db"


def _connect():
    conn = store.connect(cache_path(), _SCHEMA)
    # Swept on open, not on write: an offline session caches nothing and would keep yesterday's terms forever.
    conn.execute("DELETE FROM responses WHERE fetched_at < ?", (time.time() - RETENTION_SECONDS,))
    return conn


def _ttl_for(state: str) -> float:
    return RETENTION_SECONDS if state in ANSWERED else FAILURE_RETENTION


def _fresh(fetched_at: float, payload: str) -> SourceResult | None:
    data = json.loads(payload)
    if time.time() - fetched_at > _ttl_for(data["state"]):
        return None
    findings = tuple(Finding(**f) for f in data.get("findings", []))
    return SourceResult(
        source_id=data["source_id"],
        state=data["state"],
        findings=findings,
        detail=data.get("detail"),
        elapsed_ms=data.get("elapsed_ms", 0),
        # From the row, not the payload: the payload carries its own fetched_at and it would be the stale one.
        fetched_at=fetched_at,
    )


def _load(source_id: str, entity_type, value: str) -> SourceResult | None:
    if not cache_path().exists():
        return None  # a miss must not bring the store into being; only storing a response does
    with _connect() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE source_id = ? AND entity_type = ? AND value = ?",
            (source_id, str(entity_type), value),
        ).fetchone()
    return _fresh(*row) if row else None


def cached_results(entity_type, value: str) -> dict[str, SourceResult]:
    """Every fresh stored response for one reading, one query: a page has a dozen panels and opened a store each."""
    if not cache_path().exists():
        return {}
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT fetched_at, payload FROM responses WHERE entity_type = ? AND value = ?",
                (str(entity_type), value),
            ).fetchall()
    except Exception:  # noqa: BLE001 -- a broken cache must never break a render
        return {}
    fresh = (_fresh(*row) for row in rows)
    return {r.source_id: r for r in fresh if r}


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
    """A stored response if one is still fresh, making no request. Never raises: a cache hit spends no egress."""
    try:
        return _load(source_id, entity_type, value)
    except Exception:  # noqa: BLE001 -- a broken cache must never break a render
        return None


# One task per key while it runs: a reload mid-check joins it instead of launching a second identical run.
_IN_FLIGHT: dict[tuple[str, str, str], asyncio.Task] = {}


def in_flight(source_id, entity_type, value) -> bool:
    return (source_id, str(entity_type), value) in _IN_FLIGHT


async def _run_and_store(runner, source_id, value, entity_type, client, use_cache: bool) -> SourceResult:
    result = await runner(source_id, value, entity_type, client)
    if use_cache:
        try:  # noqa: SIM105
            _store(result, entity_type, value)
        except Exception:  # noqa: BLE001 -- failing to cache is not failing to fetch
            pass
    return result


async def run_cached(
    source_id, value, entity_type, client, *, use_cache: bool = True, refresh: bool = False, runner=run_fetcher
) -> SourceResult:
    """`runner` with a read-through cache and in-flight coalescing; failures get the shorter FAILURE_RETENTION.

    `use_cache` off means never touch the cache (privacy); `refresh` means ignore the stored answer but still write.
    `runner` defaults to the fetcher registry; the link checker passes its own so verdicts share this machinery.
    """
    if use_cache and not refresh and (hit := cached_result(source_id, entity_type, value)) is not None:
        return hit
    key = (source_id, str(entity_type), value)
    task = _IN_FLIGHT.get(key)
    if refresh or task is None or task.done():  # refresh means a new run even beside one already going
        task = asyncio.ensure_future(_run_and_store(runner, source_id, value, entity_type, client, use_cache))
        _IN_FLIGHT[key] = task
        task.add_done_callback(lambda t: _IN_FLIGHT.pop(key, None) if _IN_FLIGHT.get(key) is t else None)
    # Shielded: the browser dropping this request (a reload) must not cancel a run other waiters share.
    return await asyncio.shield(task)
