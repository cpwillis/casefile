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
