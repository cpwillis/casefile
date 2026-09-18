"""Probe catalogue links. Opt-in, because it is one request per link from your IP to several dozen third parties.

Only 404 and 410 read as missing: 43 of 78 apparent catalogue failures were bot-protection 403s, not dead links.
"""

import asyncio
from collections import Counter

import httpx

from casefile.cache import cached_result, run_cached
from casefile.fetchers import Finding, SourceResult, State
from casefile.fetchers.http import domain_slot, request

SOURCE_ID = "linkcheck"  # the cache key prefix for verdicts; not a fetcher, so never a panel

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
            resp = await request(client, "GET", url, follow_redirects=False)
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


async def check_links(links, client: httpx.AsyncClient, checkpoint=None) -> dict[str, str]:
    """One verdict per link id. Never raises: a probe that fell over is its own verdict.

    `checkpoint` carries the verdicts of a run a restart interrupted, so those links are not probed a second time.
    """
    done = checkpoint.load() if checkpoint else {}
    budget = asyncio.Semaphore(_CONCURRENCY)

    async def one(link):
        if link.id in done:
            return done[link.id]
        async with budget:
            verdict = await check_link(link.url, client)
        done[link.id] = verdict
        if checkpoint:
            checkpoint.save(done)  # throttled there, so this is not a write per link
        return verdict

    verdicts = await asyncio.gather(*(one(link) for link in links))
    return dict(zip((link.id for link in links), verdicts, strict=True))


def tally(verdicts: dict[str, str]) -> Counter:
    return Counter(verdicts.values())


def _as_verdicts(result: SourceResult | None) -> dict[str, str] | None:
    return {f.label: f.value for f in result.findings} if result else None


def verdicts_from(hit: SourceResult | None) -> dict[str, str] | None:
    """The verdicts a stored check holds, or None: a check that reached nothing is not a result."""
    return _as_verdicts(hit) if hit and hit.state == State.OK else None


def cached_verdicts(entity_type, value: str) -> dict[str, str] | None:
    """Verdicts from an earlier check of this reading, or None. Spends no egress."""
    return verdicts_from(cached_result(SOURCE_ID, entity_type, value))


async def check_links_cached(links, entity_type, value, client: httpx.AsyncClient, refresh=False) -> dict[str, str]:
    """check_links through the response cache: a reload or a return to this search must not re-probe every link."""

    async def runner(source_id, _value, _entity_type, client, checkpoint=None):
        verdicts = await check_links(links, client, checkpoint)
        # Every probe failing is the network, not the links: keep it for minutes like any failed source, not a day.
        state = State.OK if set(verdicts.values()) - {UNREACHABLE} else State.ERROR
        return SourceResult(source_id, state, tuple(Finding(label=k, value=v) for k, v in verdicts.items()))

    result = await run_cached(SOURCE_ID, value, entity_type, client, refresh=refresh, runner=runner)
    return _as_verdicts(result) or {}
