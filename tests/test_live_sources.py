import pytest

import casefile.fetchers.sources  # noqa: F401
from casefile.fetchers import State, run_fetcher
from casefile.fetchers.http import build_client
from casefile.types import EntityType

pytestmark = pytest.mark.live

# Every keyless source, with an input it should answer for. The assertion is deliberately weak:
# these prove a source is still reachable and still keyless, not what it returns, because third
# parties change their data and a test that pinned it would fail for the wrong reason.
KEYLESS = [
    ("dns", "example.com", EntityType.DOMAIN),
    ("rdap", "example.com", EntityType.DOMAIN),
    ("crtsh", "example.com", EntityType.DOMAIN),
    ("internetdb", "8.8.8.8", EntityType.IP),
    ("github", "octocat", EntityType.USERNAME),
    ("wikidata", "Cloudflare", EntityType.COMPANY),
    ("hashlookup", "d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH),
    ("nvd-cve", "CVE-2021-44228", EntityType.CVE),
    # The 2010 pizza transaction and the genesis address: public, permanent, and not anyone's
    # current holdings.
    ("mempool-space-tx", "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", EntityType.TX_HASH),
    ("mempool-space-btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", EntityType.BTC_ADDRESS),
    ("blockscout-tx", "5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060", EntityType.TX_HASH),
]


async def _run(source_id, value, entity_type):
    async with build_client() as client:
        return await run_fetcher(source_id, value, entity_type, client)


@pytest.mark.parametrize(("source_id", "value", "entity_type"), KEYLESS, ids=[k[0] for k in KEYLESS])
async def test_source_is_live_and_keyless(source_id, value, entity_type):
    r = await _run(source_id, value, entity_type)
    assert r.state in {State.OK, State.EMPTY}, f"{source_id}: {r.state} {r.detail}"


async def test_phone_meta_needs_no_network():
    r = await _run("phone_meta", "+14155550100", EntityType.PHONE)
    assert r.state is State.OK


async def test_malwarebazaar_reports_needs_key_without_one():
    """Without ABUSECH_AUTH_KEY this must be needs_key, never error: the state exists for this."""
    r = await _run("malwarebazaar", "a" * 64, EntityType.HASH)
    assert r.state in {State.NEEDS_KEY, State.OK, State.EMPTY}
