from casefile.cache import RETENTION_SECONDS, cache_path, clear_cache, run_cached
from casefile.fetchers import Finding, State, fetcher
from casefile.types import EntityType


def test_cache_path_follows_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_path() == tmp_path / "casefile" / "cache.db"


async def test_second_call_inside_ttl_does_not_re_run_the_fetcher():
    calls = 0

    @fetcher(id="cache-hit", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    first = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    second = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    assert calls == 1
    assert first.findings == second.findings
    assert second.state == State.OK


async def test_no_cache_bypasses_the_cache():
    calls = 0

    @fetcher(id="cache-bypass", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None, use_cache=False)
    assert calls == 2


async def test_expired_entries_are_re_fetched():
    calls = 0

    @fetcher(id="cache-ttl", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None, ttl=0)
    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None, ttl=0)
    assert calls == 2


async def test_a_failure_is_held_briefly_rather_than_for_the_full_day():
    """Reloading a page must not re-hammer a source that just 502'd, but a transient outage has
    to clear itself without --clear-cache. So a failure is cached, on a much shorter clock."""
    from casefile.cache import FAILURE_RETENTION, _ttl_for

    calls = 0

    @fetcher(id="cache-error", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        raise ValueError("boom")

    first = await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    assert first.state == State.ERROR
    assert calls == 1, "a reload re-queried a source that had just failed"
    assert _ttl_for(State.ERROR) == FAILURE_RETENTION
    assert _ttl_for(State.OK) == RETENTION_SECONDS
    assert FAILURE_RETENTION < RETENTION_SECONDS / 100


async def test_a_stale_failure_is_retried_once_its_short_clock_runs_out():
    calls = 0

    @fetcher(id="cache-error-stale", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        raise ValueError("boom")

    await run_cached("cache-error-stale", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-error-stale", "example.com", EntityType.DOMAIN, None, ttl=0)
    assert calls == 2


async def test_no_cache_neither_reads_nor_writes():
    """--no-cache is a privacy control, so it must not leave a copy behind either."""
    calls = 0

    @fetcher(id="cache-untouched", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="n", value="1")]

    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None, use_cache=False)
    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-untouched", "example.com", EntityType.DOMAIN, None)
    assert calls == 2, "the --no-cache run wrote to the cache"


async def test_a_forced_refresh_requeries_and_replaces_the_stored_answer():
    """The per-panel refresh control: you have a cached answer and want a current one."""
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
    # and the refresh replaced what is stored, rather than leaving the stale one behind
    assert (await run_cached("cache-refresh", "example.com", EntityType.DOMAIN, None)).findings[0].value == "2"


async def test_empty_is_cached_because_it_is_a_real_answer():
    calls = 0

    @fetcher(id="cache-empty", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return []

    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    assert calls == 1


async def test_clear_cache_empties_it():
    @fetcher(id="cache-clear", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return [Finding(label="A", value="1")]

    await run_cached("cache-clear", "example.com", EntityType.DOMAIN, None)
    assert clear_cache() >= 1
    assert clear_cache() == 0


async def test_different_values_are_separate_entries():
    calls = 0

    @fetcher(id="cache-keys", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value=value)]

    await run_cached("cache-keys", "a.example", EntityType.DOMAIN, None)
    await run_cached("cache-keys", "b.example", EntityType.DOMAIN, None)
    assert calls == 2


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
    """The README promises 24 hour retention, which means removal, not just invalidation.

    Asserted through a read, not a write: a session that fetches nothing cacheable still has to
    collect expired rows, or the retention promise only holds for people who keep searching.
    """
    import time as _time

    from casefile.cache import _connect, _load, _store
    from casefile.fetchers import SourceResult, State

    _store(SourceResult("cache-stale", State.OK), EntityType.DOMAIN, "old.example")
    with _connect() as conn:
        conn.execute("UPDATE responses SET fetched_at = ?", (_time.time() - 200000,))
    _load("cache-stale", EntityType.DOMAIN, "old.example", ttl=RETENTION_SECONDS)
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
    assert result.state == State.OK  # the lookup still succeeded


async def test_same_value_under_two_types_does_not_collide():
    calls = []

    @fetcher(id="cache-twotype", accepts=[EntityType.DOMAIN, EntityType.COMPANY])
    async def f(value, entity_type, client):
        calls.append(entity_type)
        return [Finding(label=str(entity_type), value=value)]

    await run_cached("cache-twotype", "acme.example", EntityType.DOMAIN, None)
    await run_cached("cache-twotype", "acme.example", EntityType.COMPANY, None)
    assert calls == [EntityType.DOMAIN, EntityType.COMPANY]
