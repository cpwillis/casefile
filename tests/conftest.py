"""Fixtures shared by the whole suite."""

import pytest


@pytest.fixture(autouse=True)
def no_politeness_sleeps(request, monkeypatch):
    """Zero the outbound jitter and retry backoff for everything but the live suite.

    They exist to be polite to third parties. A MockTransport has nobody to be polite to, and
    they were 88% of the suite's wall time: 16.1s to 1.9s. The `live` guard is load-bearing,
    because `make live` really does hit several hundred sites.
    """
    if "live" not in request.keywords:
        monkeypatch.setattr("casefile.fetchers.http.JITTER", 0.0)
        monkeypatch.setattr("casefile.fetchers.http.BACKOFF", 0.0)


@pytest.fixture(autouse=True)
def isolated_xdg(tmp_path, monkeypatch):
    """Point both stores at tmp_path, for every test, always.

    Autouse and global rather than per-file: the two stores are reached from more places than
    their own tests. Rendering a panel reads the cases store and writes the response cache, so
    isolating one without the other leaves a test one mock away from writing to the real home
    directory. Separate subdirectories so a test asserting on one store's directory contents
    cannot see the other's files.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
