import asyncio

import httpx
import pytest

from casefile.fetchers import RateLimited
from casefile.fetchers.http import USER_AGENT, build_client, domain_slot, get_json


def test_user_agent_names_the_project_and_version():
    assert USER_AGENT.startswith("casefile/")
    assert "github.com/cpwillis/casefile" in USER_AGENT


def test_build_client_sets_the_user_agent_and_timeouts():
    client = build_client()
    assert client.headers["user-agent"] == USER_AGENT
    assert client.timeout.connect == 5.0
    assert client.timeout.read == 20.0


async def test_domain_slot_caps_concurrency_per_host():
    active = 0
    peak = 0

    async def worker():
        nonlocal active, peak
        async with domain_slot("h.test"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(*(worker() for _ in range(12)))
    assert peak <= 4  # per-host cap


async def test_get_json_retries_once_then_raises_rate_limited():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, text="slow down")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RateLimited):
            await get_json(client, "https://h.test/x", "h.test")
    assert calls == 2  # original plus one retry


async def test_get_json_returns_on_success():
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await get_json(client, "https://h.test/x", "h.test")
    assert resp.json() == {"ok": True}
