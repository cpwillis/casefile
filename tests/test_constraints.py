"""Tests that defend decisions rather than behaviour. A failure here is a reversal."""

from pathlib import Path

from starlette.testclient import TestClient

from casefile.detect import detect
from casefile.web.app import app


def test_app_has_no_startup_hooks():
    """A browser-opening startup hook would fire under TestClient and launch a browser in CI.

    Starlette exposes the default (no custom startup) as a `_DefaultLifespan`; anything else
    means a lifespan or startup handler was registered, which is where such a bug would live.
    """
    assert type(app.router.lifespan_context).__name__ == "_DefaultLifespan"


def test_cli_and_web_render_the_same_readings():
    """The demo is a prerender of the web app, so the two must never diverge."""
    text = TestClient(app).get("/q", params={"v": "example.com"}).text
    for candidate in detect("example.com"):
        assert f'id="type-{candidate.type.value}"' in text


def test_no_network_dependency_in_this_phase():
    """Phase 1 must not import httpx anywhere in the package."""
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    offenders = [p.name for p in package.rglob("*.py") if "import httpx" in p.read_text()]
    assert not offenders, f"httpx imported in phase 1: {offenders}"
