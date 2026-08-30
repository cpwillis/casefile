import pytest


@pytest.fixture(autouse=True)
def no_politeness_sleeps(request, monkeypatch):
    """Zero jitter/backoff outside the live suite: a MockTransport has nobody to be polite to.

    The `live` guard is load-bearing: `make live` really does hit several hundred sites.
    """
    if "live" not in request.keywords:
        monkeypatch.setattr("casefile.fetchers.http.JITTER", 0.0)
        monkeypatch.setattr("casefile.fetchers.http.BACKOFF", 0.0)


@pytest.fixture(autouse=True)
def isolated_xdg(tmp_path, monkeypatch):
    """Both stores, every test: a panel read touches both, and one un-isolated store writes to the real home dir."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
