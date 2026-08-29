"""Fixtures shared by the whole suite."""

import pytest


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
