"""Probe catalogue links. Opt-in, because it is one request per link from your IP to several dozen third parties.

Only 404 and 410 read as missing: 43 of 78 apparent catalogue failures were bot-protection 403s, not dead links.
"""

import asyncio
from collections import Counter

import httpx

from casefile.fetchers.http import domain_slot

LIVE = "live"
MISSING = "missing"
BLOCKED = "blocked"
REDIRECTED = "redirected"
UNREACHABLE = "unreachable"

# What a status code is allowed to prove. Anything absent from this map is "cannot tell".
_VERDICTS = {404: MISSING, 410: MISSING, 401: BLOCKED, 403: BLOCKED, 429: BLOCKED, 451: BLOCKED}


async def check_link(url: str, client: httpx.AsyncClient) -> str:
    try:
        host = httpx.URL(url).host
    except (httpx.InvalidURL, ValueError, TypeError):
        return UNREACHABLE
    try:
        async with domain_slot(host):
            # follow_redirects=False on purpose: a missing profile redirected home would answer 200 and read as a hit.
            resp = await client.get(url, follow_redirects=False)
    except Exception:  # noqa: BLE001 -- a probe that fails is a verdict, not an error
        return UNREACHABLE
    if verdict := _VERDICTS.get(resp.status_code):
        return verdict
    if 200 <= resp.status_code < 300:
        return LIVE
    if 300 <= resp.status_code < 400:
        return REDIRECTED
    return UNREACHABLE


# Its own budget: ~48 links per domain put 48 waiters on the global slot and queued every panel behind the check.
_CONCURRENCY = 8


async def check_links(links, client: httpx.AsyncClient) -> dict[str, str]:
    """One verdict per link id. Never raises: a probe that fell over is its own verdict."""
    budget = asyncio.Semaphore(_CONCURRENCY)

    async def one(link):
        async with budget:
            return await check_link(link.url, client)

    verdicts = await asyncio.gather(*(one(link) for link in links))
    return dict(zip((link.id for link in links), verdicts, strict=True))


def tally(verdicts: dict[str, str]) -> Counter:
    return Counter(verdicts.values())
