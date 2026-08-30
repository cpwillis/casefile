import asyncio

import httpx
import pytest
from helpers import mock_client, responder

from casefile.fetchers import RateLimited, http
from casefile.fetchers.http import USER_AGENT, build_client, domain_slot


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
    assert peak <= 4


async def test_domain_slot_caps_global_concurrency_across_many_hosts():
    active = 0
    peak = 0

    async def worker(host):
        nonlocal active, peak
        async with domain_slot(host):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    # 30 hosts, 2 workers each: the per-host cap of 4 cannot bind, so any observed cap proves the global semaphore.
    hosts = [f"h{i}.test" for i in range(30) for _ in range(2)]
    await asyncio.gather(*(worker(h) for h in hosts))
    assert peak <= 20
    assert peak > 4  # confirms real contention, ie the per-host cap isn't what limited it


def test_domain_slot_survives_a_second_event_loop():
    """asyncio.Semaphore binds to the loop that first contends it, so a second asyncio.run() must not raise."""

    async def contend():
        async def worker():
            async with domain_slot("second-loop.test"):
                await asyncio.sleep(0.01)

        await asyncio.gather(*(worker() for _ in range(8)))  # over the per-host cap of 4

    asyncio.run(contend())  # first loop: forces the semaphores to bind here
    asyncio.run(contend())  # second, independent loop: must not raise RuntimeError


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_retries_once_then_raises_rate_limited(method):
    """Both verbs go through one fetch(), so both must show the same one-retry policy."""
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, text="slow down")

    async with mock_client(handler) as client:
        with pytest.raises(RateLimited):
            await http.fetch(client, "https://h.test/x", method=method)
    assert calls == 2


async def test_get_returns_on_success():
    async with responder(200, json={"ok": True}) as client:
        resp = await http.fetch(client, "https://h.test/x")
    assert resp.json() == {"ok": True}


async def test_get_allow_returns_404_without_raising():
    async with responder(404, json={"message": "Not Found"}) as client:
        resp = await http.fetch(client, "https://h.test/x", allow=(404,))
    assert resp.status_code == 404


async def test_get_still_raises_on_unallowed_404():
    async with responder(404, json={"message": "Not Found"}) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await http.fetch(client, "https://h.test/x")


async def test_post_sends_form_data_and_returns_body():
    seen = {}

    def handler(request):
        seen["body"] = request.content.decode()
        seen["method"] = request.method
        return httpx.Response(200, json={"query_status": "ok"})

    async with mock_client(handler) as client:
        resp = await http.fetch(client, "https://h.test/api", method="POST", data={"query": "get_info", "hash": "abc"})
    assert seen["method"] == "POST"
    assert "query=get_info" in seen["body"]
    assert resp.json() == {"query_status": "ok"}


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_one_retry_on_429_and_5xx(status):
    """Only the 429 half was covered: the 5xx retry branch could be deleted with the suite green."""
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(status) if calls == 1 else httpx.Response(200, json={"ok": True})

    async with mock_client(handler) as client:
        resp = await http.fetch(client, "https://h.test/x")
    assert calls == 2
    assert resp.status_code == 200
