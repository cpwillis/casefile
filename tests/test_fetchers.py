import pytest

from casefile.fetchers import (
    Finding,
    NeedsKey,
    RateLimited,
    SourceResult,
    State,
    fetcher,
    fetchers_for,
    has_fetcher,
    registered_fetcher,
)
from casefile.types import EntityType


def test_state_names_are_exact():
    assert (State.OK, State.EMPTY, State.NEEDS_KEY, State.RATE_LIMITED, State.TIMEOUT, State.ERROR) == (
        "ok",
        "empty",
        "needs_key",
        "rate_limited",
        "timeout",
        "error",
    )


def test_finding_defaults_url_to_none():
    assert Finding(label="A", value="1").url is None


def test_source_result_is_flat_and_defaults_empty():
    r = SourceResult(source_id="x", state=State.EMPTY)
    assert r.findings == ()
    assert r.detail is None
    assert r.elapsed_ms == 0


def test_exceptions_exist():
    assert issubclass(NeedsKey, Exception)
    assert issubclass(RateLimited, Exception)


def test_register_and_look_up_a_fetcher():
    @fetcher(id="probe", accepts=[EntityType.DOMAIN, EntityType.EMAIL])
    async def probe(value, entity_type, client):
        return []

    rec = registered_fetcher("probe")
    assert rec is not None
    assert rec.id == "probe"
    assert rec.accepts == (EntityType.DOMAIN, EntityType.EMAIL)
    assert rec.func is probe
    assert has_fetcher("probe")
    assert "probe" in fetchers_for(EntityType.DOMAIN)
    assert "probe" not in fetchers_for(EntityType.IP)


def test_unknown_id_returns_none():
    assert registered_fetcher("nope") is None
    assert not has_fetcher("nope")


def test_duplicate_id_is_rejected():
    @fetcher(id="dupe", accepts=[EntityType.IP])
    async def a(value, entity_type, client):
        return []

    with pytest.raises(ValueError, match="dupe"):

        @fetcher(id="dupe", accepts=[EntityType.IP])
        async def b(value, entity_type, client):
            return []
