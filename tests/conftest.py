import contextlib

import helpers
import httpx
import pytest


@pytest.fixture(scope="session", autouse=True)
def _persistent_test_clients():
    """Enter both TestClients once for the session instead of per-request (was ~6.3ms vs ~1.6ms/request).

    Safe under per-test XDG isolation: cache_path()/cases_path() read os.environ at call time, not at
    client/app startup, so a persistent event loop never pins a stale store path.
    """
    with contextlib.ExitStack() as stack:
        stack.enter_context(helpers.client)
        stack.enter_context(helpers.bare_client)
        yield


@pytest.fixture(autouse=True)
def no_politeness_sleeps(request, monkeypatch):
    """Zero jitter/backoff outside the live suite: a MockTransport has nobody to be polite to.

    The `live` guard is load-bearing: `make live` really does hit several hundred sites.
    """
    if "live" not in request.keywords:
        monkeypatch.setattr("casefile.fetchers.http.JITTER", 0.0)
        monkeypatch.setattr("casefile.fetchers.http.BACKOFF", 0.0)


@pytest.fixture(autouse=True)
def no_real_network(request, monkeypatch):
    """Fail fast on a real network hit outside the live suite; MockTransport-based tests never reach this."""
    if "live" not in request.keywords:

        async def _blocked(self, req):
            raise AssertionError(f"unexpected real network request: {req.method} {req.url}")

        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _blocked)


@pytest.fixture(autouse=True)
def isolated_xdg(tmp_path, monkeypatch):
    """Both stores, every test: a panel read touches both, and one un-isolated store writes to the real home dir."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
