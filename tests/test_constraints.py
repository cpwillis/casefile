"""Tests that defend decisions rather than behaviour. A failure here is a reversal."""

import ast
import re
from pathlib import Path
from urllib.parse import urlsplit

from helpers import client

from casefile.detect import detect
from casefile.types import EntityType
from casefile.web.app import app


def test_app_has_no_startup_hooks():
    """A browser-opening startup hook would fire under TestClient and launch a browser in CI.

    Starlette exposes the default (no custom startup) as a `_DefaultLifespan`; anything else
    means a lifespan or startup handler was registered, which is where such a bug would live.
    """
    # Asserted by driving the lifespan rather than by naming Starlette's private default class,
    # which an upgrade could rename with no defect present. The risk this guards is real: a
    # startup hook that opened a browser would fire for every importer, including the test suite
    # and --build-demo.
    import webbrowser

    from starlette.testclient import TestClient

    opened = []
    real = webbrowser.open
    webbrowser.open = lambda *a, **k: opened.append(a)
    try:
        with TestClient(app, base_url="http://127.0.0.1") as c:
            assert c.get("/").status_code == 200
    finally:
        webbrowser.open = real
    assert opened == [], "starting the app opened a browser"


def test_the_web_page_renders_every_reading_detect_found():
    """Detection and the page must agree: a reading with no section is a silently dropped lead."""
    text = client.get("/q", params={"v": "example.com"}).text
    for candidate in detect("example.com"):
        assert f'id="links-{candidate.type.value}"' in text


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
            if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", literal):
                continue  # an address or a range: dots and digits, but not a number you can ring
            digits = re.sub(r"\D", "", literal)
            if len(digits) < 10 or not any(c.type is EntityType.PHONE for c in detect(literal)):
                continue
            if not RESERVED_PHONE.match(digits):
                offenders.append(f"{path.name}:{node.lineno} {literal!r}")
    assert not offenders, "fixtures using non-reserved phone numbers: " + ", ".join(offenders)


# A label of its own, anywhere in the host: example.com, sub.example.co.uk, h.test, x.invalid.
RESERVED_LABEL = frozenset({"example", "test", "invalid", "localhost", "local"})
REGISTRABLE = re.compile(r"\.(com|net|org|io|dev|co|uk|au|me|app|sh|lu|info|biz|xyz)$", re.I)


def _hosts_the_project_targets() -> set[str]:
    """Hosts casefile genuinely reaches: the catalogue, the fetchers, and its own project links.

    Derived rather than hand-listed, so adding a catalogue entry never means editing this test.
    """
    from casefile.catalog import load_catalog

    hosts = {urlsplit(source.url).hostname for source in load_catalog()}
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    for path in package.rglob("*.py"):
        hosts |= {urlsplit(u).hostname for u in re.findall(r"https?://[^\s\"'<>)\]]+", path.read_text())}
    hosts |= {"github.com", "pypi.org", "docs.astral.sh", "cpwillis.dev", "casefile.cpwillis.dev", "osint.cpwillis.dev"}
    return {h for h in hosts if h}


def test_no_fixture_or_doc_names_a_real_world_host():
    """Fixtures must be synthetic. This is the check that was missing when a real investigation
    target was transcribed into the test suite of a public OSINT repo.

    A registrable host in a test or in the README must be one the project legitimately targets.
    Anything else belongs to somebody, and an OSINT repo is the worst place to publish it.
    """
    allowed = _hosts_the_project_targets()
    offenders = set()
    files = [*Path(__file__).parent.glob("*.py"), Path(__file__).resolve().parents[1] / "README.md"]
    for path in files:
        # Escapes are decoded first: a source file holding an escaped newline inside a
        # string otherwise yields a host glued to the letter that follows it, which is a
        # tokenising artifact rather than a finding.
        text = path.read_text().replace("\\n", "\n").replace("\\t", "\t")
        for raw in re.findall(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", text):
            host = raw.rstrip(".").lower()
            if host.startswith(("casefile.", "tests.", "helpers.")) or not REGISTRABLE.search(host):
                continue  # module paths, filenames, versions: not hostnames
            if RESERVED_LABEL & set(host.split(".")) or host in allowed:
                continue
            offenders.add(f"{path.name}: {host}")
    assert not offenders, "non-reserved hosts in fixtures or docs: " + ", ".join(sorted(offenders))
