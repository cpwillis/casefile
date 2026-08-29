"""Tests that defend decisions rather than behaviour. A failure here is a reversal."""

import ast
import re
from pathlib import Path

from helpers import client

from casefile.detect import detect
from casefile.types import EntityType
from casefile.web.app import app


def test_app_has_no_startup_hooks():
    """A browser-opening startup hook would fire under TestClient and launch a browser in CI.

    Starlette exposes the default (no custom startup) as a `_DefaultLifespan`; anything else
    means a lifespan or startup handler was registered, which is where such a bug would live.
    """
    assert type(app.router.lifespan_context).__name__ == "_DefaultLifespan"


def test_the_web_page_renders_every_reading_detect_found():
    """Detection and the page must agree: a reading with no section is a silently dropped lead."""
    text = client.get("/q", params={"v": "example.com"}).text
    for candidate in detect("example.com"):
        assert f'id="type-{candidate.type.value}"' in text


def test_the_demo_has_no_templates_of_its_own():
    """It renders through the real ones with demo=True. A demo_*.html file is the fork coming back."""
    templates = Path(__file__).resolve().parents[1] / "src" / "casefile" / "web" / "templates"
    forks = sorted(p.name for p in templates.glob("demo_*.html"))
    assert forks == [], f"demo templates have reappeared: {forks}"


def test_async_client_is_constructed_in_one_place():
    """Every fetcher must use the shared client so the User-Agent and timeouts are uniform."""
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    offenders = [
        p.relative_to(package).as_posix()
        for p in package.rglob("*.py")
        if "httpx.AsyncClient(" in p.read_text() and p.relative_to(package).as_posix() != "fetchers/http.py"
    ]
    assert offenders == [], f"AsyncClient built outside fetchers/http.py: {offenders}"


# Numbers reserved for fiction, and the only ones a fixture may use.
# AU: ACMA reserves 5550 xxxx in each geographic area code. NANP: 555-0100 to 555-0199.
RESERVED_PHONE = re.compile(r"^(?:61[2378]5550\d{4}|0?[2378]5550\d{4}|1?\d{3}55501\d{2})$")


def test_no_fixture_uses_a_dialable_real_phone_number():
    """A test number must not be able to ring a real person or organisation.

    The suite is full of digit strings that are not phone numbers (IMO, MMSI, dates, ports), so
    the filter is: anything casefile itself reads as a phone AND is long enough to be a real
    subscriber number has to come from a reserved fiction range.
    """
    offenders = []
    for path in sorted(Path(__file__).parent.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            literal = node.value.strip()
            digits = re.sub(r"\D", "", literal)
            if len(digits) < 10 or not any(c.type is EntityType.PHONE for c in detect(literal)):
                continue
            if not RESERVED_PHONE.match(digits):
                offenders.append(f"{path.name}:{node.lineno} {literal!r}")
    assert not offenders, "fixtures using non-reserved phone numbers: " + ", ".join(offenders)
