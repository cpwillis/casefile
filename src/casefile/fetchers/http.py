"""The one place an httpx client is built, and the shared outbound rate limiter."""

import asyncio
import random
import weakref
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx

from casefile import __version__
from casefile.fetchers import RateLimited

USER_AGENT = f"casefile/{__version__} (+https://github.com/cpwillis/casefile)"

# asyncio.Semaphore binds to whichever loop first contends it, so module-level singletons
# blow up with "bound to a different event loop" the second time a fresh loop uses them
# (eg a second asyncio.run() call). Keyed per running loop instead, cleaned up via weakref
# when the loop is garbage collected.
_HostSlots = defaultdict[str, asyncio.Semaphore]
_LoopSlots = tuple[asyncio.Semaphore, _HostSlots]
_SLOTS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _LoopSlots] = weakref.WeakKeyDictionary()


def _slots_for_running_loop() -> _LoopSlots:
    loop = asyncio.get_running_loop()
    if loop not in _SLOTS:
        _SLOTS[loop] = (asyncio.Semaphore(20), defaultdict(lambda: asyncio.Semaphore(4)))
    return _SLOTS[loop]


def build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"user-agent": USER_AGENT},
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=20.0),
        follow_redirects=True,
    )


@asynccontextmanager
async def domain_slot(host: str):
    global_slot, per_host = _slots_for_running_loop()
    async with global_slot, per_host[host]:
        await asyncio.sleep(random.uniform(0, 0.25))  # jitter, politeness not security
        yield


async def fetch(
    client: httpx.AsyncClient, url: str, *, method: str = "GET", allow: tuple[int, ...] = (), **kwargs
) -> httpx.Response:
    """One request through the limiter, one retry on 429/5xx, then give up.

    `allow` lists statuses a caller wants back rather than raised. The rate-limit host is derived
    from the url rather than passed alongside it: two spellings of one host that must agree, at
    every call site, and a mismatch silently opens a second semaphore for a host nobody is
    talking to, which is the cap quietly ceasing to apply.
    """
    host = httpx.URL(url).host
    async with domain_slot(host):
        resp = await client.request(method, url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(0.5)  # single backoff
            resp = await client.request(method, url, **kwargs)
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        if resp.status_code in allow:
            return resp
        resp.raise_for_status()
        return resp
