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
CREATE TABLE IF NOT EXISTS jobs (
    source_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    started_at  REAL NOT NULL,
    progress    TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (source_id, entity_type, value)
);
"""
# One write a second, not one per site: a 600-site sweep would otherwise be 600 transactions to save 600 crumbs.
CHECKPOINT_INTERVAL = 1.0


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


def _job_start(key: tuple[str, str, str], reset: bool = False) -> None:
    """Record a run so a restart can pick it up. OR IGNORE, so a resume keeps the crumbs it is resuming from."""
    with _connect() as conn:
        if reset:  # a refresh must re-probe, not replay the crumbs of the run it replaces
            conn.execute("DELETE FROM jobs WHERE source_id = ? AND entity_type = ? AND value = ?", key)
        conn.execute(
            "INSERT OR IGNORE INTO jobs (source_id, entity_type, value, started_at) VALUES (?, ?, ?, ?)",
            (*key, time.time()),
        )


def forget_job(source_id, entity_type, value) -> None:
    """Drop a job row: the run finished, or it can never be resumed and must not be retried on every start."""
    try:  # noqa: SIM105
        with _connect() as conn:
            conn.execute(
                "DELETE FROM jobs WHERE source_id = ? AND entity_type = ? AND value = ?",
                (source_id, str(entity_type), value),
            )
    except Exception:  # noqa: BLE001 -- a broken cache must never break a run
        pass


def pending_jobs() -> list[tuple[str, str, str]]:
    """Runs a restart interrupted, oldest first. Reads only: a miss must not bring the store into being."""
    if not cache_path().exists():
        return []
    try:
        with _connect() as conn:
            rows = conn.execute("SELECT source_id, entity_type, value FROM jobs ORDER BY started_at").fetchall()
    except Exception:  # noqa: BLE001 -- a broken cache must never break startup
        return []
    return [tuple(row) for row in rows]


class Checkpoint:
    """Crumbs a long run drops into its job row, so a resumed run skips the items that already finished.

    Generic on purpose: a runner with nothing worth resuming from is handed one and ignores it.
    """

    def __init__(self, key: tuple[str, str, str]):
        self._key = key
        self._saved_at = 0.0

    def load(self) -> dict:
        try:
            with _connect() as conn:
                row = conn.execute(
                    "SELECT progress FROM jobs WHERE source_id = ? AND entity_type = ? AND value = ?", self._key
                ).fetchone()
        except Exception:  # noqa: BLE001 -- no crumbs just means starting over, slower but correct
            return {}
        return json.loads(row[0]) if row and row[0] else {}

    def save(self, progress: dict) -> None:
        now = time.monotonic()
        if now - self._saved_at < CHECKPOINT_INTERVAL:
            return
        self._saved_at = now
        try:  # noqa: SIM105
            with _connect() as conn:
                conn.execute(
                    "UPDATE jobs SET progress = ? WHERE source_id = ? AND entity_type = ? AND value = ?",
                    (json.dumps(progress), *self._key),
                )
        except Exception:  # noqa: BLE001 -- failing to checkpoint is not failing to fetch
            pass


async def _run_and_store(runner, source_id, value, entity_type, client, use_cache: bool, refresh: bool) -> SourceResult:
    key = (source_id, str(entity_type), value)
    # use_cache off is the privacy path: nothing is written, so there is no job row and nothing to resume.
    checkpoint = None
    if use_cache:
        try:
            _job_start(key, reset=refresh)
            checkpoint = Checkpoint(key)
        except Exception:  # noqa: BLE001 -- a run that cannot be resumed is still a run
            pass
    try:
        result = await runner(source_id, value, entity_type, client, checkpoint)
    finally:
        # Gone whether the run succeeded, failed or was cancelled, so a normal CLI exit leaves no stale row.
        if use_cache:
            forget_job(source_id, entity_type, value)
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
    A run is recorded in `jobs` while it lasts, and handed a Checkpoint, so a restart can resume it where it stopped.
    """
    if use_cache and not refresh and (hit := cached_result(source_id, entity_type, value)) is not None:
        return hit
    key = (source_id, str(entity_type), value)
    task = _IN_FLIGHT.get(key)
    if refresh or task is None or task.done():  # refresh means a new run even beside one already going
        coro = _run_and_store(runner, source_id, value, entity_type, client, use_cache, refresh)
        task = asyncio.ensure_future(coro)
        _IN_FLIGHT[key] = task
        task.add_done_callback(lambda t: _IN_FLIGHT.pop(key, None) if _IN_FLIGHT.get(key) is t else None)
    # Shielded: the browser dropping this request (a reload) must not cancel a run other waiters share.
    return await asyncio.shield(task)
