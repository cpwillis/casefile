"""Test helpers importable from any test module (pytest puts tests/ on sys.path)."""

import httpx
from starlette.testclient import TestClient

from casefile.fetchers import SourceResult, State
from casefile.web.app import app

# base_url is load-bearing, not decoration: TrustedHostMiddleware pins Host, so a bare
# TestClient(app) gets a 400 from the middleware rather than whatever the test meant to check.
client = TestClient(app, base_url="http://127.0.0.1")


def mock_client(handler) -> httpx.AsyncClient:
    """An AsyncClient whose requests are answered by `handler` instead of the network."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def stub_result(*findings, state=State.OK, detail=None):
    """A run_cached replacement returning one fixed result for whatever it is asked about.

    The cache keywords are accepted and ignored so one stub serves every caller: the CLI passes
    use_cache, the panel route passes refresh.
    """

    async def fake(source_id, value, entity_type, client=None, *, use_cache=True, refresh=False):
        return SourceResult(source_id, state, tuple(findings), detail)

    return fake
