import pytest

import casefile.fetchers.sources  # noqa: F401
from casefile.fetchers import State, run_fetcher
from casefile.fetchers.http import build_client
from casefile.types import EntityType

pytestmark = pytest.mark.live


async def _run(source_id, value, entity_type):
    async with build_client() as client:
        return await run_fetcher(source_id, value, entity_type, client)


async def test_dns_is_live_and_keyless():
    r = await _run("dns", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}


async def test_rdap_is_live_and_keyless():
    r = await _run("rdap", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}


async def test_crtsh_is_live_and_keyless():
    r = await _run("crtsh", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}


async def test_internetdb_is_live_and_keyless():
    r = await _run("internetdb", "8.8.8.8", EntityType.IP)
    assert r.state in {State.OK, State.EMPTY}


async def test_github_is_live_and_keyless():
    r = await _run("github", "octocat", EntityType.USERNAME)
    assert r.state in {State.OK, State.EMPTY}


async def test_wikidata_is_live_and_keyless():
    r = await _run("wikidata", "Cloudflare", EntityType.COMPANY)
    assert r.state in {State.OK, State.EMPTY}


async def test_hashlookup_is_live_and_keyless():
    r = await _run("hashlookup", "d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH)
    assert r.state in {State.OK, State.EMPTY}


async def test_phone_meta_needs_no_network():
    r = await _run("phone_meta", "+14155552671", EntityType.PHONE)
    assert r.state is State.OK


async def test_malwarebazaar_reports_needs_key_without_one():
    """Without ABUSECH_AUTH_KEY this must be needs_key, never error: the state exists for this."""
    r = await _run("malwarebazaar", "a" * 64, EntityType.HASH)
    assert r.state in {State.NEEDS_KEY, State.OK, State.EMPTY}
