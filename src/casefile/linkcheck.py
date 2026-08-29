"""Probe catalogue links so a dead one is visible without opening it.

Opt-in, like the WhatsMyName checker and for the same reason: it is one request per link, sent
from your IP to several dozen third parties, which is not something to do on every page load.

The verdicts are deliberately coarse, and three of the five mean "cannot tell". Earlier catalogue
verification found 43 of 78 apparent failures were bot-protection 403s rather than dead links, so
a checker that collapsed those into "missing" would manufacture exactly the confident false
negative this tool exists to avoid. Only 404 and 410 are reported as nothing-there.
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
            # Redirects are not followed on purpose: a site that sends a missing profile to its
            # home page would otherwise answer 200 and read as a hit.
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


async def check_links(links, client: httpx.AsyncClient) -> dict[str, str]:
    """One verdict per link id. Never raises: a probe that fell over is its own verdict."""
    verdicts = await asyncio.gather(*(check_link(link.url, client) for link in links))
    return dict(zip((link.id for link in links), verdicts, strict=True))


def tally(verdicts: dict[str, str]) -> Counter:
    return Counter(verdicts.values())
