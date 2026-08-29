from casefile.cache import cache_path, clear_cache, run_cached
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


async def test_errors_are_never_cached():
    calls = 0

    @fetcher(id="cache-error", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        raise ValueError("boom")

    first = await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    assert first.state == State.ERROR
    assert calls == 2, "a transient failure must not be cached for the whole TTL"


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
    """The README promises 24 hour retention, which means removal, not just invalidation."""
    import time as _time

    from casefile.cache import _connect, _store
    from casefile.fetchers import SourceResult, State

    _store(SourceResult("cache-stale", State.OK), EntityType.DOMAIN, "old.example")
    with _connect() as conn:
        conn.execute("UPDATE responses SET fetched_at = ?", (_time.time() - 200000,))
    with _connect() as conn:  # the prune runs on connect
        remaining = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
    assert remaining == 0


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
