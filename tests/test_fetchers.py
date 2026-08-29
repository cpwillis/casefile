import httpx
import pytest

from casefile.fetchers import (
    Finding,
    NeedsKey,
    RateLimited,
    SourceResult,
    State,
    fetcher,
    fetchers_for,
    registered_fetcher,
    run_fetcher,
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
    assert "probe" in [r.id for r in fetchers_for(EntityType.DOMAIN)]
    assert "probe" not in [r.id for r in fetchers_for(EntityType.IP)]


def test_unknown_id_returns_none():
    assert registered_fetcher("nope") is None


def test_duplicate_id_is_rejected():
    @fetcher(id="dupe", accepts=[EntityType.IP])
    async def a(value, entity_type, client):
        return []

    with pytest.raises(ValueError, match="dupe"):

        @fetcher(id="dupe", accepts=[EntityType.IP])
        async def b(value, entity_type, client):
            return []


def _register(id, behaviour):
    @fetcher(id=id, accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return await behaviour(value)

    return f


async def _ok(value):
    return [Finding(label="A", value=value)]


async def _empty(value):
    return []


async def _needs_key(value):
    raise NeedsKey("set X")


async def _rate(value):
    raise RateLimited("429")


async def _timeout(value):
    raise httpx.ReadTimeout("slow")


async def _boom(value):
    raise ValueError("kaboom")


async def test_states_map_from_fetcher_outcomes():
    _register("s-ok", _ok)
    _register("s-empty", _empty)
    _register("s-key", _needs_key)
    _register("s-rate", _rate)
    _register("s-timeout", _timeout)
    _register("s-boom", _boom)
    cases = {
        "s-ok": State.OK,
        "s-empty": State.EMPTY,
        "s-key": State.NEEDS_KEY,
        "s-rate": State.RATE_LIMITED,
        "s-timeout": State.TIMEOUT,
        "s-boom": State.ERROR,
    }
    for sid, expected in cases.items():
        r = await run_fetcher(sid, "example.com", EntityType.DOMAIN, client=None)
        assert r.state == expected, sid
        assert r.source_id == sid


async def test_ok_carries_findings_and_error_carries_detail():
    _register("s-ok2", _ok)
    _register("s-boom2", _boom)
    ok = await run_fetcher("s-ok2", "example.com", EntityType.DOMAIN, client=None)
    assert ok.findings == (Finding(label="A", value="example.com"),)
    err = await run_fetcher("s-boom2", "example.com", EntityType.DOMAIN, client=None)
    assert err.detail == "kaboom"


async def test_unknown_source_is_an_error_not_a_crash():
    r = await run_fetcher("ghost", "example.com", EntityType.DOMAIN, client=None)
    assert r.state == State.ERROR
    assert "ghost" in r.detail


def test_on_demand_defaults_to_false_and_is_recorded():
    @fetcher(id="cheap-probe", accepts=[EntityType.DOMAIN])
    async def cheap(value, entity_type, client):
        return []

    @fetcher(id="pricey-probe", accepts=[EntityType.DOMAIN], on_demand=True, cost_note="lots of requests")
    async def pricey(value, entity_type, client):
        return []

    assert registered_fetcher("cheap-probe").on_demand is False
    assert registered_fetcher("pricey-probe").on_demand is True
    assert registered_fetcher("pricey-probe").cost_note == "lots of requests"
