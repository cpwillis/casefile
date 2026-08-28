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


def test_async_client_is_constructed_in_one_place():
    """Every fetcher must use the shared client so the User-Agent and timeouts are uniform."""
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    offenders = [
        p.relative_to(package).as_posix()
        for p in package.rglob("*.py")
        if "httpx.AsyncClient(" in p.read_text() and p.name != "http.py"
    ]
    assert offenders == [], f"AsyncClient built outside fetchers/http.py: {offenders}"
