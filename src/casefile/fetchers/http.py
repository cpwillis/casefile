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

# asyncio.Semaphore binds to the loop that first contends it: a module-level one dies under a second asyncio.run().
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


# Named so tests can zero them.
JITTER = 0.25
BACKOFF = 0.5


_CLIENTS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, httpx.AsyncClient] = weakref.WeakKeyDictionary()


def shared_client() -> httpx.AsyncClient:
    """One client per loop so panels reuse connections; never closed on purpose, the process outlives it."""
    loop = asyncio.get_running_loop()
    client = _CLIENTS.get(loop)
    if client is None or client.is_closed:
        client = build_client()
        _CLIENTS[loop] = client
    return client


@asynccontextmanager
async def domain_slot(host: str):
    """Jitter only when the host slot is already busy: unconditional jitter cost the dns panel 83ms -> 784ms."""
    global_slot, per_host = _slots_for_running_loop()
    slot = per_host[host]
    crowded = slot.locked()
    async with global_slot, slot:
        if crowded and JITTER:
            await asyncio.sleep(random.uniform(0, JITTER))
        yield


async def fetch(
    client: httpx.AsyncClient, url: str, *, method: str = "GET", allow: tuple[int, ...] = (), **kwargs
) -> httpx.Response:
    """One request through the limiter, one retry on 429/5xx; `allow` lists statuses returned rather than raised.

    The host is derived from the url, never passed alongside it: a mismatch opens a second semaphore and the cap
    silently stops applying.
    """
    host = httpx.URL(url).host
    async with domain_slot(host):
        resp = await client.request(method, url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(BACKOFF)
            resp = await client.request(method, url, **kwargs)
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        if resp.status_code in allow:
            return resp
        resp.raise_for_status()
        return resp
