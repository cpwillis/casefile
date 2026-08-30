"""Test helpers importable from any test module (pytest puts tests/ on sys.path)."""

import httpx
from starlette.testclient import TestClient

from casefile.fetchers import SourceResult, State
from casefile.web.app import app

# Both defaults model what a browser actually sends, and both are load-bearing:
# TrustedHostMiddleware pins Host, and every route that mutates or spends egress requires
# Sec-Fetch-Site: same-origin. Without them a test gets a 400 or a 403 rather than the thing it
# meant to check. Tests asserting a refusal pass their own header, which overrides these.
client = TestClient(app, base_url="http://127.0.0.1", headers={"sec-fetch-site": "same-origin"})


def mock_client(handler) -> httpx.AsyncClient:
    """An AsyncClient whose requests are answered by `handler` instead of the network."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def responder(status: int = 200, **kwargs) -> httpx.AsyncClient:
    """A client that answers every request the same way.

    Most fetcher tests do not care what was requested, only what comes back, and were spending
    three lines on a throwaway handler to say so. Tests that assert on the request keep writing
    their own handler and passing it to mock_client.
    """
    return mock_client(lambda request: httpx.Response(status, **kwargs))


def stub_result(*findings, state=State.OK, detail=None):
    """A run_cached replacement returning one fixed result for whatever it is asked about.

    The cache keywords are accepted and ignored so one stub serves every caller: the CLI passes
    use_cache, the panel route passes refresh.
    """

    async def fake(source_id, value, entity_type, client=None, *, use_cache=True, refresh=False):
        return SourceResult(source_id, state, tuple(findings), detail)

    return fake


# The same app with no browser headers at all, for the tests that assert a refusal.
bare_client = TestClient(app, base_url="http://127.0.0.1")
