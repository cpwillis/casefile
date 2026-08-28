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


async def get_json(client: httpx.AsyncClient, url: str, host: str, **kwargs) -> httpx.Response:
    """GET with one retry on 429/5xx. Raises RateLimited if still 429 after the retry."""
    async with domain_slot(host):
        resp = await client.get(url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(0.5)  # single backoff
            resp = await client.get(url, **kwargs)
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        resp.raise_for_status()
        return resp
