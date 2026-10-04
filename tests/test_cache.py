import pytest

from casefile.cache import RETENTION_SECONDS, cache_path, clear_cache, run_cached
from casefile.fetchers import Finding, State, fetcher
from casefile.types import EntityType


def counting(source_id, *, findings=(("A", "1"),), raises=None):
    """Register a fetcher that counts its calls; returns the list it appends to."""
    calls = []

    @fetcher(id=source_id, accepts=[EntityType.DOMAIN])
    async def _f(value, entity_type, client):
        calls.append(value)
        if raises is not None:
            raise raises
        return [Finding(label=label, value=v) for label, v in findings]

    return calls


def test_cache_path_follows_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_path() == tmp_path / "casefile" / "cache.db"


async def test_second_call_inside_ttl_does_not_re_run_the_fetcher():
    calls = counting("cache-hit")

    first = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    second = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    assert len(calls) == 1
    assert first.findings == second.findings
    assert second.state == State.OK


async def test_no_cache_bypasses_the_cache():
    calls = counting("cache-bypass")

    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None, use_cache=False)
    assert len(calls) == 2


async def test_expired_entries_are_re_fetched(monkeypatch):
    calls = counting("cache-ttl")

    monkeypatch.setattr("casefile.cache.RETENTION_SECONDS", 0)
    monkeypatch.setattr("casefile.cache.FAILURE_RETENTION", 0)
    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None)
    assert len(calls) == 2


async def test_a_failure_is_held_briefly_rather_than_for_the_full_day():
    """A failure must not be re-hammered on reload, but a transient outage has to clear without --clear-cache."""
    from casefile.cache import FAILURE_RETENTION, _ttl_for

    calls = counting("cache-error", raises=ValueError("boom"))

    first = await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    assert first.state == State.ERROR
    assert len(calls) == 1, "a reload re-queried a source that had just failed"
    assert _ttl_for(State.ERROR) == FAILURE_RETENTION
    assert _ttl_for(State.OK) == RETENTION_SECONDS
    assert _ttl_for(State.EMPTY) == RETENTION_SECONDS  # a source that answered with nothing is not a failure
    assert FAILURE_RETENTION < RETENTION_SECONDS / 100


async def test_a_stale_failure_is_retried_once_its_short_clock_runs_out(monkeypatch):
    calls = counting("cache-error-stale", raises=ValueError("boom"))

    await run_cached("cache-error-stale", "example.com", EntityType.DOMAIN, None)
    monkeypatch.setattr("casefile.cache.FAILURE_RETENTION", 0)
    await run_cached("cache-error-stale", "example.com", EntityType.DOMAIN, None)
    assert len(calls) == 2


async def test_no_cache_neither_reads_nor_writes():
    """--no-cache is a privacy control, so it must not leave a copy behind either."""
    calls = counting("cache-untouched", findings=(("n", "1"),))

    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None, use_cache=False)
    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None)
    assert len(calls) == 2, "the --no-cache run wrote to the cache"


async def test_a_forced_refresh_requeries_and_replaces_the_stored_answer():
    calls = 0

    @fetcher(id="cache-refresh", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="n", value=str(calls))]

    assert (await run_cached("cache-refresh", "example.com", EntityType.DOMAIN, None)).findings[0].value == "1"
    assert (await run_cached("cache-refresh", "example.com", EntityType.DOMAIN, None)).findings[0].value == "1"
    fresh = await run_cached("cache-refresh", "example.com", EntityType.DOMAIN, None, refresh=True)
    assert fresh.findings[0].value == "2"
    assert (await run_cached("cache-refresh", "example.com", EntityType.DOMAIN, None)).findings[0].value == "2"


async def test_empty_is_cached_because_it_is_a_real_answer():
    calls = counting("cache-empty", findings=())

    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    assert len(calls) == 1


async def test_clear_cache_empties_it():
    @fetcher(id="cache-clear", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return [Finding(label="A", value="1")]

    await run_cached("cache-clear", "example.com", EntityType.DOMAIN, None)
    assert clear_cache() >= 1
    assert clear_cache() == 0


async def test_different_values_are_separate_entries():
    # this one's finding echoes the value, so it keeps its own stub
    calls = []

    @fetcher(id="cache-keys", accepts=[EntityType.DOMAIN])
    async def _f(value, entity_type, client):
        calls.append(value)
        return [Finding(label="A", value=value)]

    await run_cached("cache-keys", "a.example", EntityType.DOMAIN, None)
    await run_cached("cache-keys", "b.example", EntityType.DOMAIN, None)
    assert len(calls) == 2


async def test_clear_cache_actually_removes_the_data_from_disk():
    """DELETE leaves freed pages readable, so the file itself must go."""

    @fetcher(id="cache-shred", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return [Finding(label="A", value="1")]

    await run_cached("cache-shred", "secret-term.example", EntityType.DOMAIN, None)
    assert cache_path().exists()
    clear_cache()
    assert not cache_path().exists()


async def test_stale_rows_are_pruned_from_disk_not_just_ignored():
    """24h retention means rows are removed, not just ignored, and a read must prune them or only searchers get it."""
    import time as _time

    from casefile.cache import _connect, _load, _store
    from casefile.fetchers import SourceResult, State

    _store(SourceResult("cache-stale", State.OK), EntityType.DOMAIN, "old.example")
    with _connect() as conn:
        conn.execute("UPDATE responses SET fetched_at = ?", (_time.time() - 200000,))
    _load("cache-stale", EntityType.DOMAIN, "old.example")
    with _connect() as conn:
        rows = [r[0] for r in conn.execute("SELECT source_id FROM responses")]
    assert rows == [], f"stale row survived a read: {rows}"


async def test_a_corrupt_cache_degrades_to_an_uncached_lookup():
    @fetcher(id="cache-corrupt", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return [Finding(label="A", value="1")]

    cache_path().parent.mkdir(parents=True, exist_ok=True)
    cache_path().write_bytes(b"this is not a sqlite database")
    result = await run_cached("cache-corrupt", "example.com", EntityType.DOMAIN, None)
    assert result.state == State.OK


async def test_same_value_under_two_types_does_not_collide():
    calls = []

    @fetcher(id="cache-twotype", accepts=[EntityType.DOMAIN, EntityType.COMPANY])
    async def f(value, entity_type, client):
        calls.append(entity_type)
        return [Finding(label=str(entity_type), value=value)]

    await run_cached("cache-twotype", "acme.example", EntityType.DOMAIN, None)
    await run_cached("cache-twotype", "acme.example", EntityType.COMPANY, None)
    assert calls == [EntityType.DOMAIN, EntityType.COMPANY]


def test_a_store_is_created_owner_only(tmp_path, monkeypatch):
    """A store of someone's searches and third-party payloads must not be world-readable."""
    import stat

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    from casefile.store import connect

    p = tmp_path / "sub" / "s.db"
    connect(p, "CREATE TABLE IF NOT EXISTS t (x)").close()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700


def test_purge_removes_wal_and_shm_sidecars_too(tmp_path):
    """Rollback mode never leaves these, but README promises they're swept if present; the loop must cover them."""
    from casefile.store import connect, purge

    p = tmp_path / "s.db"
    connect(p, "CREATE TABLE IF NOT EXISTS t (x)").close()
    p.with_name(p.name + "-wal").write_bytes(b"")
    p.with_name(p.name + "-shm").write_bytes(b"")
    purge(p, "t")
    leftovers = [f.name for f in tmp_path.iterdir()]
    assert leftovers == [], f"purge left {leftovers} behind"


async def test_a_cache_hit_reports_when_it_was_fetched_not_epoch_zero(monkeypatch, tmp_path):
    """fetched_at comes from the row, not the payload; a swap to the payload would misreport age as 1970."""
    import time

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    from casefile.cache import _load, _store
    from casefile.fetchers import SourceResult, State

    before = time.time()
    _store(SourceResult("dns", State.OK), EntityType.DOMAIN, "example.com")
    hit = _load("dns", EntityType.DOMAIN, "example.com")
    assert hit is not None
    assert hit.fetched_at >= before  # a real timestamp, not 0.0


def test_a_relative_xdg_path_is_ignored_not_used_verbatim(monkeypatch):
    """A relative XDG_CACHE_HOME would put the store under whatever cwd the tool ran from; the spec says ignore it."""
    monkeypatch.setenv("XDG_CACHE_HOME", "relative/dir")
    assert cache_path().is_absolute()
    from pathlib import Path

    assert str(cache_path()).startswith(str(Path.home()))


async def test_identical_runs_in_flight_are_coalesced_and_visible(tmp_path, monkeypatch):
    """A reload mid-check must join the running check, not launch a second one."""
    import asyncio

    from casefile.cache import in_flight, run_cached
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    started = asyncio.Event()
    release = asyncio.Event()
    runs = []

    async def slow(source_id, value, entity_type, client, checkpoint=None):
        runs.append(1)
        started.set()
        await release.wait()
        return SourceResult(source_id, State.EMPTY)

    first = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, runner=slow))
    await started.wait()
    assert in_flight("dns", EntityType.DOMAIN, "example.com")
    second = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, runner=slow))
    await asyncio.sleep(0)
    release.set()
    assert (await first).state == (await second).state == State.EMPTY
    assert runs == [1]
    assert not in_flight("dns", EntityType.DOMAIN, "example.com")


async def test_a_dropped_waiter_does_not_cancel_the_shared_run(tmp_path, monkeypatch):
    import asyncio

    from casefile.cache import cached_result, run_cached
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    release = asyncio.Event()

    async def slow(source_id, value, entity_type, client, checkpoint=None):
        await release.wait()
        return SourceResult(source_id, State.EMPTY)

    waiter = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, runner=slow))
    await asyncio.sleep(0)
    waiter.cancel()  # the browser reloaded
    await asyncio.sleep(0)
    release.set()
    await asyncio.sleep(0.01)
    assert cached_result("dns", EntityType.DOMAIN, "example.com") is not None  # the run finished and was stored


async def test_refresh_starts_a_new_run_beside_one_already_going(tmp_path, monkeypatch):
    import asyncio

    from casefile.cache import run_cached
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    release = asyncio.Event()
    runs = []

    async def slow(source_id, value, entity_type, client, checkpoint=None):
        runs.append(1)
        await release.wait()
        return SourceResult(source_id, State.EMPTY)

    first = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, runner=slow))
    await asyncio.sleep(0)
    second = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, refresh=True, runner=slow))
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(first, second)
    assert runs == [1, 1]


async def test_a_job_row_records_the_run_and_is_gone_once_it_ends():
    """The point of the table: a restart mid-run must find the run on disk, a finished one must not be resumed."""
    from casefile.cache import pending_jobs

    seen = []

    @fetcher(id="job-row", accepts=[EntityType.DOMAIN])
    async def _f(value, entity_type, client):
        seen.extend(pending_jobs())
        return [Finding(label="A", value="1")]

    await run_cached("job-row", "example.com", EntityType.DOMAIN, None)
    assert seen == [("job-row", "domain", "example.com")]
    assert pending_jobs() == []


async def test_a_failed_run_clears_its_job_row_so_a_broken_source_cannot_loop():
    from casefile.cache import pending_jobs

    counting("job-fail", raises=ValueError("boom"))
    await run_cached("job-fail", "example.com", EntityType.DOMAIN, None)
    assert pending_jobs() == []


async def test_no_cache_records_no_job_because_nothing_about_it_is_stored():
    """--no-cache is the privacy path: a resumable row naming what was searched would defeat it."""
    from casefile.cache import pending_jobs

    seen = []

    @fetcher(id="job-nocache", accepts=[EntityType.DOMAIN])
    async def _f(value, entity_type, client):
        seen.append(pending_jobs())
        return []

    await run_cached("job-nocache", "example.com", EntityType.DOMAIN, None, use_cache=False)
    assert seen == [[]]


async def test_a_run_that_contacts_the_target_records_no_job_but_is_still_cached(monkeypatch):
    """No row means a restart can never visit a site unprompted; the 24h answer still spares a second visit."""
    from casefile.cache import cached_result, pending_jobs
    from casefile.fetchers import _REGISTRY, Registered

    seen = []

    async def _f(value, entity_type, client):
        seen.append(pending_jobs())
        return [Finding(label="status", value="200 OK")]

    # setitem, not @fetcher: undone after the test, so no page elsewhere in the run grows a visit panel
    monkeypatch.setitem(_REGISTRY, "job-visit", Registered("job-visit", (EntityType.DOMAIN,), _f, contacts_target=True))
    await run_cached("job-visit", "example.com", EntityType.DOMAIN, None)
    assert seen == [[]]
    assert cached_result("job-visit", EntityType.DOMAIN, "example.com") is not None


async def test_clear_cache_purges_jobs_too():
    """It unlinks the file, so the jobs table goes with it; a surviving row would name a purged search."""
    from casefile.cache import _job_start, pending_jobs

    _job_start(("job-purge", "domain", "example.com"))
    assert pending_jobs() == [("job-purge", "domain", "example.com")]
    clear_cache()
    assert pending_jobs() == []


async def test_a_checkpoint_is_readable_by_the_run_that_resumes_it():
    from casefile.cache import Checkpoint, _job_start

    key = ("job-crumbs", "domain", "example.com")
    _job_start(key)
    Checkpoint(key).save({"a": "done"})
    assert Checkpoint(key).load() == {"a": "done"}


async def test_checkpoint_writes_are_batched_rather_than_one_per_item():
    """600 sites must not be 600 transactions; losing the last second of crumbs is the trade."""
    from casefile.cache import Checkpoint, _job_start

    key = ("job-batch", "domain", "example.com")
    _job_start(key)
    saver = Checkpoint(key)
    saver.save({"a": "done"})
    saver.save({"a": "done", "b": "done"})
    assert Checkpoint(key).load() == {"a": "done"}


async def test_a_refresh_does_not_replay_the_crumbs_of_the_run_it_replaces():
    from casefile.cache import Checkpoint, _job_start

    key = ("job-refresh", "domain", "example.com")
    _job_start(key)
    Checkpoint(key).save({"a": "done"})
    _job_start(key, reset=True)
    assert Checkpoint(key).load() == {}


async def test_a_cancelled_run_keeps_its_job_row_for_the_next_start(tmp_path, monkeypatch):
    """ctrl-c is the normal restart: the row and its crumbs must outlive it, or nothing ever resumes."""
    import asyncio

    from casefile.cache import pending_jobs, run_cached
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    started = asyncio.Event()

    async def slow(source_id, value, entity_type, client, checkpoint=None):
        started.set()
        await asyncio.sleep(3600)
        return SourceResult(source_id, State.EMPTY)

    task = asyncio.ensure_future(run_cached("dns", "example.com", EntityType.DOMAIN, None, runner=slow))
    await started.wait()
    assert pending_jobs() == [("dns", "domain", "example.com")]
    task.cancel()
    await asyncio.sleep(0)
    assert pending_jobs() == [("dns", "domain", "example.com")]

    async def broken(source_id, value, entity_type, client, checkpoint=None):
        raise RuntimeError("no")

    with pytest.raises(RuntimeError):
        await run_cached("dns", "example.com", EntityType.DOMAIN, None, refresh=True, runner=broken)
    assert pending_jobs() == []  # a run that failed on its own is not retried on every start


def test_stores_run_in_wal_mode_and_purge_removes_the_sidecars(tmp_path, monkeypatch):
    from casefile.cache import _store, cache_path
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    _store(SourceResult("dns", State.EMPTY), EntityType.DOMAIN, "example.com")
    import sqlite3

    assert sqlite3.connect(cache_path()).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    clear_cache()
    assert not list(cache_path().parent.glob("cache.db*"))
