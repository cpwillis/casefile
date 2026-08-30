"""Test helpers importable from any test module (pytest puts tests/ on sys.path)."""

import httpx
from starlette.testclient import TestClient

from casefile.fetchers import SourceResult, State
from casefile.web.app import app

# TrustedHostMiddleware pins Host and writes require Sec-Fetch-Site: same-origin, so without both every route 400s/403s.
client = TestClient(app, base_url="http://127.0.0.1", headers={"sec-fetch-site": "same-origin"})


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def responder(status: int = 200, **kwargs) -> httpx.AsyncClient:
    """A client that answers every request the same way, for tests that do not care what was asked."""
    return mock_client(lambda request: httpx.Response(status, **kwargs))


def stub_result(*findings, state=State.OK, detail=None):
    """A run_cached replacement returning one fixed result; the cache kwargs are accepted and ignored."""

    async def fake(source_id, value, entity_type, client=None, *, use_cache=True, refresh=False):
        return SourceResult(source_id, state, tuple(findings), detail)

    return fake


# For the tests that assert a refusal: no browser headers at all.
bare_client = TestClient(app, base_url="http://127.0.0.1")
