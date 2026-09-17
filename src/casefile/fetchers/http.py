"""The one place an httpx client is built, and the shared outbound rate limiter."""

import asyncio
import ipaddress
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


async def refuse_local_targets(request: httpx.Request) -> None:
    """Runs on every hop, redirects included: a source must not be able to bounce the fetcher onto this machine."""
    host = request.url.host
    try:
        local = not ipaddress.ip_address(host).is_global
    except ValueError:
        local = host == "localhost" or host.endswith(".localhost")
    if local:
        raise httpx.RequestError(f"refused to fetch {host}", request=request)


def build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"user-agent": USER_AGENT},
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=20.0),
        follow_redirects=True,
        event_hooks={"request": [refuse_local_targets]},
    )


# A JSON answer is KBs. Read through a cap because httpx inflates gzip in full: a 200KB bomb was 200MB in memory.
MAX_BODY = 4 * 1024 * 1024


async def request(
    client: httpx.AsyncClient, method: str, url: str, *, follow_redirects=httpx.USE_CLIENT_DEFAULT, **kwargs
) -> httpx.Response:
    """client.request with the body read through MAX_BODY. Every outbound call goes through here."""
    req = client.build_request(method, url, **kwargs)
    resp = await client.send(req, stream=True, follow_redirects=follow_redirects)
    body, size = [], 0
    try:
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > MAX_BODY:
                raise httpx.ReadError(f"{req.url.host} sent more than {MAX_BODY} bytes", request=req)
            body.append(chunk)
    finally:
        await resp.aclose()
    # Already decoded, so the encoding and length headers would describe bytes that are no longer there.
    headers = [(k, v) for k, v in resp.headers.raw if k.lower() not in (b"content-encoding", b"content-length")]
    return httpx.Response(resp.status_code, headers=headers, content=b"".join(body), request=req)


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
        resp = await request(client, method, url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(BACKOFF)
            resp = await request(client, method, url, **kwargs)
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        # GitHub and NVD signal an exhausted unauthenticated quota with a 403 and a zeroed remaining header,
        # not a 429; without this it reads as a plain error rather than "try again later".
        if resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0":
            raise RateLimited(f"{host} rate limit reached")
        if resp.status_code in allow:
            return resp
        resp.raise_for_status()
        return resp
