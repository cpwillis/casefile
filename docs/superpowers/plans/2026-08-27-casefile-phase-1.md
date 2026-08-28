# casefile Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `0.1.0`: `uvx casefile` opens a browser where pasting any identifier returns every relevant OSINT pivot as a link, with zero network calls.

**Architecture:** A pure-function detector maps an input string to a ranked tuple of candidate entity types with per-type normalised values. A TOML catalogue maps entity types to sources, each holding a URL template. A Starlette app renders a sticky-rail-plus-pane page of those links; an argparse CLI renders the same data as text or JSON. Nothing in this phase touches the network.

**Tech Stack:** Python 3.12, Starlette, uvicorn, Jinja2, stdlib `tomllib`/`argparse`/`dataclasses`/`urllib.parse`. Ruff and pytest for dev.

**Spec:** [docs/superpowers/specs/2026-08-27-casefile-design.md](../specs/2026-08-27-casefile-design.md)

**Master plan:** [docs/superpowers/plans/2026-08-27-casefile-master-plan.md](2026-08-27-casefile-master-plan.md)

## Global Constraints

- Python `>=3.12`.
- Five runtime dependencies for the whole project, total: `httpx`, `starlette`, `uvicorn`, `jinja2`, `phonenumbers`. Phase 1 adds only `starlette`, `uvicorn`, `jinja2`. Adding a sixth is a decision, not an implementation detail.
- Each dependency is added to `pyproject.toml` by the task that first imports it.
- `phonenumbers` is **not** a phase 1 dependency. Phone normalisation here is regex-only; libphonenumber arrives in phase 4 with the fetcher that needs it.
- MIT, copyright holder `cpwillis`. No GPL code imported.
- Catalogue is TOML, parsed with stdlib `tomllib`.
- Exactly one positional value on the CLI. No `--input-file`, no target lists, no batch mode, ever.
- No query log, no telemetry.
- Catalogue URLs must be `https://`. Enforced at load time; a non-https entry fails CI.
- The web app is GET-only with no mutating routes, so there is no CSRF surface to defend.
- Web app binds `127.0.0.1` only.
- Fixtures and test data contain no real person's data. Reserved ranges only: `example.com`, RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`).
- Ruff line length is 120 and CI runs `ruff check` plus `ruff format --check`. Every code block in this plan is already within that limit; keep it that way.
- Commits are bare lowercase one-line, linear, GPG-signed. No `--no-gpg-sign`.
- Never push. The repo owner pushes.

## File Structure

| File | Responsibility |
|---|---|
| `src/casefile/types.py` | `EntityType` enum and `Candidate` dataclass. Imported by everything, imports nothing. |
| `src/casefile/detect.py` | Three tiers of pure detector functions plus `detect()`. |
| `src/casefile/catalog.py` | `Source` dataclass, TOML loading, lookup by type, URL building. |
| `src/casefile/report.py` | `Link`, `Section`, and `build_report()`. The single source of the result shape, consumed by the text, JSON and HTML renderers. |
| `src/casefile/cli.py` | argparse entry point: text output, JSON output, app launch. |
| `src/casefile/web/app.py` | Starlette routes and template wiring. |
| `src/casefile/web/templates/*.html` | `base.html`, `index.html`, `result.html`. |
| `src/casefile/web/static/casefile.css` | Layout, including the 900px collapse. |
| `src/casefile/web/static/casefile.js` | Link filter only. Nothing else needs JS. |
| `src/casefile/catalog/*.toml` | Link catalogue, one file per category. |
| `tests/*.py` | One test module per source module. |
| `.github/workflows/ci.yml` | Lint and test on push and pull request. |

`types.py` exists separately from `detect.py` so that `catalog.py` can validate `accepts` values without importing the detectors.

---

### Task 1: Test harness and CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `Makefile`
- Create: `tests/test_smoke.py` (deleted again in Task 2, see below)
- Modify: `pyproject.toml` (pytest markers and default marker filter)

**Interfaces:**
- Consumes: nothing.
- Produces: a green `pytest` and `ruff` baseline every later task depends on.

- [ ] **Step 1: Write the failing test**

Create `tests/test_smoke.py`:

```python
def test_package_imports():
    import casefile

    assert casefile.__version__
```

- [ ] **Step 2: Run it to confirm the harness works**

Run: `uv run pytest tests/test_smoke.py -v`
Expected: PASS. If `uv` reports no dev environment, run `uv sync` first.

- [ ] **Step 3: Add the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - run: uv sync --all-extras --dev
      - run: uv run ruff check
      - run: uv run ruff format --check
      - run: uv run pytest -q
```

`workflow_dispatch` lets the suite be run by hand from the Actions tab without pushing a
commit to trigger it.

- [ ] **Step 4: Add the local entrypoint and marker config**

Create `Makefile`:

```make
.PHONY: check test live fmt lint
check: lint test
test:
	uv run pytest
live:
	uv run pytest -m live -v
lint:
	uv run ruff check
	uv run ruff format --check
fmt:
	uv run ruff format
	uv run ruff check --fix
```

Tabs, not spaces, in the recipe lines. Make requires it.

Then replace the `[tool.pytest.ini_options]` block in `pyproject.toml` with:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = ["-m", "not live"]
markers = [
  "live: hits real third-party services. Excluded by default; run with `make live`.",
]
```

The default run never touches the network, so a contributor offline gets a full green run.
Live source checks arrive in phase 3 with the first fetchers, along with
`.github/workflows/live.yml`. See
[the test suite plan](2026-08-27-casefile-test-suite.md).

- [ ] **Step 5: Verify lint and format pass locally**

Run: `make check`
Expected: passes. Fix any formatting `ruff format` wants before committing.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml Makefile pyproject.toml tests/test_smoke.py
git commit -m "add ci workflow, makefile and test harness"
```

---

### Task 2: Entity types and tier-1 detectors

Tier 1 is the structurally unambiguous set. If the pattern matches, the input *is* that type.

**Files:**
- Create: `src/casefile/types.py`
- Create: `src/casefile/detect.py`
- Create: `tests/test_detect.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `EntityType` (`StrEnum`) with all 21 members.
  - `Candidate` frozen dataclass: `type: EntityType`, `value: str`.
  - `TIER1: tuple[tuple[EntityType, Detector], ...]` where `Detector = Callable[[str], str | None]` returning the normalised value or `None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_detect.py`:

```python
import pytest

from casefile.detect import TIER1
from casefile.types import EntityType

TIER1_DETECTORS = dict(TIER1)


@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        (EntityType.IP, "192.0.2.10", "192.0.2.10"),
        (EntityType.IP, "2001:db8::1", "2001:db8::1"),
        (EntityType.IP, "192.0.2.10/24", None),
        (EntityType.IP, "999.0.2.10", None),
        (EntityType.ASN, "AS64496", "AS64496"),
        (EntityType.ASN, "as64496", "AS64496"),
        (EntityType.ASN, "64496", None),
        (EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "abc123", None),
        (EntityType.CVE, "cve-2021-44228", "CVE-2021-44228"),
        (EntityType.CVE, "CVE-2021-44228", "CVE-2021-44228"),
        (EntityType.MAC, "00:1b:44:11:3a:b7", "00:1b:44:11:3a:b7"),
        (EntityType.MAC, "00-1B-44-11-3A-B7", "00:1b:44:11:3a:b7"),
        (EntityType.COORDINATES, "-33.8688, 151.2093", "-33.8688,151.2093"),
        (EntityType.COORDINATES, "91.0, 0.0", None),
        (EntityType.ICAO24, "7c6b2d", "7c6b2d"),
        (EntityType.BTC_ADDRESS, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
        (
            EntityType.ETH_ADDRESS,
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x52908400098527886e0f7030069857d2e4169ee7",
        ),
    ],
)
def test_tier1_detector(entity_type, raw, expected):
    assert TIER1_DETECTORS[entity_type](raw) == expected
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_detect.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.detect'`

- [ ] **Step 3: Write `types.py`**

```python
"""Entity taxonomy. Imported by everything; imports nothing."""

from dataclasses import dataclass
from enum import StrEnum


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    COMPANY = "company"
    PHONE = "phone"
    HASH = "hash"
    CVE = "cve"
    BTC_ADDRESS = "btc_address"
    ETH_ADDRESS = "eth_address"
    COORDINATES = "coordinates"
    MAC = "mac"
    VIN = "vin"
    PLATE = "plate"
    MMSI = "mmsi"
    IMO = "imo"
    ICAO24 = "icao24"
    TAIL_NUMBER = "tail_number"


@dataclass(frozen=True, slots=True)
class Candidate:
    """One plausible reading of the input, with the value normalised for that reading."""

    type: EntityType
    value: str
```

- [ ] **Step 4: Write the tier-1 detectors in `detect.py`**

```python
"""Input to ranked candidate types. Pure functions, no I/O."""

import ipaddress
import re
from collections.abc import Callable
from urllib.parse import urlsplit

from casefile.types import EntityType

Detector = Callable[[str], str | None]

_HASH_LENGTHS = {32, 40, 64}


def _ip(s: str) -> str | None:
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _asn(s: str) -> str | None:
    m = re.fullmatch(r"(?i)as(\d{1,10})", s)
    return f"AS{m.group(1)}" if m else None


def _hash(s: str) -> str | None:
    if len(s) in _HASH_LENGTHS and re.fullmatch(r"(?i)[0-9a-f]+", s):
        return s.lower()
    return None


def _cve(s: str) -> str | None:
    m = re.fullmatch(r"(?i)cve-(\d{4})-(\d{4,7})", s)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _mac(s: str) -> str | None:
    if not re.fullmatch(r"(?i)[0-9a-f]{2}([:-][0-9a-f]{2}){5}", s):
        return None
    return ":".join(part.lower() for part in re.split(r"[:-]", s))


def _coordinates(s: str) -> str | None:
    m = re.fullmatch(r"\s*(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*", s)
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return f"{m.group(1)},{m.group(2)}"


def _icao24(s: str) -> str | None:
    return s.lower() if re.fullmatch(r"(?i)[0-9a-f]{6}", s) and not s.isdigit() else None


def _btc_address(s: str) -> str | None:
    if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", s):
        return s
    if re.fullmatch(r"(?i)bc1[02-9ac-hj-np-z]{11,71}", s):
        return s.lower()
    return None


def _eth_address(s: str) -> str | None:
    return s.lower() if re.fullmatch(r"(?i)0x[0-9a-f]{40}", s) else None


TIER1: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.IP, _ip),
    (EntityType.ASN, _asn),
    (EntityType.HASH, _hash),
    (EntityType.CVE, _cve),
    (EntityType.MAC, _mac),
    (EntityType.COORDINATES, _coordinates),
    (EntityType.ICAO24, _icao24),
    (EntityType.BTC_ADDRESS, _btc_address),
    (EntityType.ETH_ADDRESS, _eth_address),
)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_detect.py -v`
Expected: PASS, 19 cases.

Note on `_icao24`: a six-hex-digit string is ambiguous with a plate or a short id, and an all-digit string is far more likely to be something else, so all-digits is rejected. This is a deliberate false-negative trade, not an oversight.

- [ ] **Step 6: Delete the smoke test**

```bash
git rm tests/test_smoke.py
```

It existed to prove the harness ran in Task 1. Real tests now do that, so keeping it is a
test that can only ever pass.

- [ ] **Step 7: Commit**

```bash
git add src/casefile/types.py src/casefile/detect.py tests/test_detect.py
git commit -m "add entity taxonomy and tier-1 detectors, drop smoke test"
```

---

### Task 3: Tier-2 detectors

Tier 2 is format-constrained: the pattern is strong but not proof.

**Files:**
- Modify: `src/casefile/detect.py`
- Modify: `tests/test_detect.py`

**Interfaces:**
- Consumes: `EntityType`, `Detector` from Task 2.
- Produces: `TIER2: tuple[tuple[EntityType, Detector], ...]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detect.py`, and add `TIER2` to the existing `casefile.detect`
import:

```python
TIER2_DETECTORS = dict(TIER2)


@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        (EntityType.EMAIL, "Someone@Example.COM", "someone@example.com"),
        (EntityType.EMAIL, "not-an-email", None),
        (EntityType.URL, "https://example.com/a?b=c", "https://example.com/a?b=c"),
        (EntityType.URL, "example.com", None),
        (EntityType.DOMAIN, "Example.COM", "example.com"),
        (EntityType.DOMAIN, "sub.example.co.uk", "sub.example.co.uk"),
        (EntityType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
        (EntityType.DOMAIN, "no_underscores.com", None),
        (EntityType.DOMAIN, "trailing.", None),
        (EntityType.PHONE, "+61 2 9374 4000", "+61293744000"),
        (EntityType.PHONE, "(02) 9374 4000", "0293744000"),
        (EntityType.PHONE, "123", None),
        (EntityType.PHONE, "192.0.2.10", None),
        (EntityType.PHONE, "1.800.555.0199", "18005550199"),
        (EntityType.VIN, "1HGCM82633A004352", "1HGCM82633A004352"),
        (EntityType.VIN, "1HGCM82633A00435I", None),
        (EntityType.IMO, "IMO 9074729", "9074729"),
        (EntityType.MMSI, "503000000", "503000000"),
        (EntityType.TAIL_NUMBER, "vh-oqa", "VH-OQA"),
        (EntityType.TAIL_NUMBER, "AS64496", None),
    ],
)
def test_tier2_detector(entity_type, raw, expected):
    assert TIER2_DETECTORS[entity_type](raw) == expected
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_detect.py -v`
Expected: FAIL with `ImportError: cannot import name 'TIER2'`

- [ ] **Step 3: Add the tier-2 detectors to `detect.py`**

Append below `TIER1`:

```python
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


def _email(s: str) -> str | None:
    m = re.fullmatch(r"([^@\s]+)@([^@\s]+\.[^@\s]+)", s)
    return f"{m.group(1).lower()}@{m.group(2).lower()}" if m else None


def _url(s: str) -> str | None:
    return s if re.match(r"(?i)https?://\S+$", s) else None


def _domain(s: str) -> str | None:
    try:
        candidate = s.strip().lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not re.fullmatch(rf"{_LABEL}(?:\.{_LABEL})+", candidate):
        return None
    if candidate.split(".")[-1].isdigit():
        return None
    return candidate


def _phone(s: str) -> str | None:
    """Regex-only. libphonenumber arrives in phase 4 with the fetcher that needs it."""
    if _ip(s):  # 192.0.2.10 is seven digits and all-dots, which would otherwise pass
        return None
    plus = s.strip().startswith("+")
    digits = re.sub(r"\D", "", s)
    if not 7 <= len(digits) <= 15:
        return None
    if not re.fullmatch(r"[\s()+\-.\d]+", s.strip()):
        return None
    return f"+{digits}" if plus else digits


def _vin(s: str) -> str | None:
    return s.upper() if re.fullmatch(r"(?i)[A-HJ-NPR-Z0-9]{17}", s) else None


def _imo(s: str) -> str | None:
    m = re.fullmatch(r"(?i)(?:imo[\s:]*)?(\d{7})", s.strip())
    return m.group(1) if m else None


def _mmsi(s: str) -> str | None:
    return s if re.fullmatch(r"\d{9}", s) else None


def _domain_from_url(value: str) -> str | None:
    """A URL is also a pivot on its host, so paste a URL and get the domain sources too."""
    host = urlsplit(value).hostname
    return _domain(host) if host else None


def _tail_number(s: str) -> str | None:
    if re.fullmatch(r"(?i)as\d+", s):  # AS64496 is an ASN, not a tail number
        return None
    return s.upper() if re.fullmatch(r"(?i)[a-z]{1,2}-?[a-z0-9]{1,5}", s) and any(c.isalpha() for c in s) else None


TIER2: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.EMAIL, _email),
    (EntityType.URL, _url),
    (EntityType.DOMAIN, _domain),
    (EntityType.PHONE, _phone),
    (EntityType.VIN, _vin),
    (EntityType.IMO, _imo),
    (EntityType.MMSI, _mmsi),
    (EntityType.TAIL_NUMBER, _tail_number),
)
```

`plate` is deliberately absent from `TIER2`: number plate formats vary so widely by jurisdiction that any regex either matches almost everything or almost nothing. It stays in `EntityType` and may hold catalogue entries, but **nothing detects it in v1**, so it is exempt from the coverage floor in Task 6. Making it reachable needs an explicit type override in the UI, which is not a phase 1 concern.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_detect.py -v`
Expected: PASS, 18 new cases on top of tier 1's 19.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/detect.py tests/test_detect.py
git commit -m "add tier-2 format-constrained detectors"
```

---

### Task 4: Tier-3 detectors and the `detect()` entry point

**Files:**
- Modify: `src/casefile/detect.py`
- Modify: `tests/test_detect.py`

**Interfaces:**
- Consumes: `TIER1`, `TIER2`, `Candidate`, `EntityType`.
- Produces: `detect(raw: str) -> tuple[Candidate, ...]`, ordered tier 1, then tier 2, then tier 3.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_detect.py`, adding `detect` to the existing import:

```python
def types_of(raw):
    return [c.type for c in detect(raw)]


def test_unambiguous_input_suppresses_free_form():
    assert types_of("192.0.2.10") == [EntityType.IP]


def test_domain_readings_are_pinned_in_order():
    assert types_of("example.com") == [
        EntityType.DOMAIN,
        EntityType.USERNAME,
        EntityType.PERSON,
        EntityType.COMPANY,
    ]


def test_url_also_yields_its_host_as_a_domain():
    result = detect("https://example.com/a?b=c")
    assert result[0].type is EntityType.URL
    domain = next(c for c in result if c.type is EntityType.DOMAIN)
    assert domain.value == "example.com"


def test_url_without_a_resolvable_host_yields_no_domain():
    assert EntityType.DOMAIN not in types_of("https://localhost/x")


def test_bare_word_is_free_form_only():
    assert types_of("cpwillis") == [EntityType.USERNAME, EntityType.PERSON, EntityType.COMPANY]


def test_two_words_are_person_and_company_not_username():
    result = types_of("Ada Lovelace")
    assert EntityType.USERNAME not in result
    assert result == [EntityType.PERSON, EntityType.COMPANY]


def test_values_are_normalised_per_candidate():
    (candidate,) = detect("CVE-2021-44228")
    assert candidate.value == "CVE-2021-44228"
    domain = next(c for c in detect("Example.COM") if c.type is EntityType.DOMAIN)
    assert domain.value == "example.com"


def test_empty_and_whitespace_yield_nothing():
    assert detect("") == ()
    assert detect("   ") == ()


def test_no_duplicate_types():
    result = types_of("example.com")
    assert len(result) == len(set(result))
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_detect.py -k 'not tier' -v`
Expected: FAIL with `ImportError: cannot import name 'detect'`

- [ ] **Step 3: Add tier 3 and `detect()` to `detect.py`**

Append:

```python
_NAMEISH = r"[A-Za-z][A-Za-z0-9 .,&'’\-]{1,59}"


def _username(s: str) -> str | None:
    s = s.strip()
    if " " in s:
        return None
    return s if re.fullmatch(r"[A-Za-z0-9._-]{2,39}", s) and any(c.isalpha() for c in s) else None


def _person(s: str) -> str | None:
    s = s.strip()
    return s if re.fullmatch(_NAMEISH, s) else None


def _company(s: str) -> str | None:
    s = s.strip()
    return s if re.fullmatch(_NAMEISH, s) else None


TIER3: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.USERNAME, _username),
    (EntityType.PERSON, _person),
    (EntityType.COMPANY, _company),
)


def detect(raw: str) -> tuple[Candidate, ...]:
    """Ranked candidate readings of `raw`, most constrained first.

    Tier 3 is suppressed entirely when a tier-1 detector matches: an IP address is not a
    plausible person, and offering it as one is noise. Tier 2 does not suppress tier 3,
    because `example.com` genuinely is both a domain and a plausible company name.
    """
    value = raw.strip()
    if not value:
        return ()

    tier1 = tuple(Candidate(t, v) for t, d in TIER1 if (v := d(value)) is not None)
    tier2 = tuple(Candidate(t, v) for t, d in TIER2 if (v := d(value)) is not None)

    have = {c.type for c in tier2}
    if EntityType.URL in have and EntityType.DOMAIN not in have and (host := _domain_from_url(value)):
        tier2 = (*tier2, Candidate(EntityType.DOMAIN, host))

    if tier1:
        return tier1 + tier2

    tier3 = tuple(Candidate(t, v) for t, d in TIER3 if (v := d(value)) is not None)
    return tier2 + tier3
```

Add `Candidate` to the existing import from `casefile.types`.

`username` deliberately survives a domain match, so `example.com` yields a username
reading too. That is mild noise now and the right call for later: WhatsMyName brings 700
username sites in phase 4, making `username` the highest-value type in the taxonomy.
Suppressing it whenever the input parses as a domain would cost far more than the noise,
because plenty of real usernames contain dots.

- [ ] **Step 4: Run the whole detect suite**

Run: `uv run pytest tests/test_detect.py -v`
Expected: all PASS, 44 cases.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/detect.py tests/test_detect.py
git commit -m "add tier-3 detectors and ranked detect entry point"
```

---

### Task 5: Catalogue loader, lookup and URL building

**Files:**
- Create: `src/casefile/catalog.py`
- Create: `src/casefile/catalog/certificates.toml`
- Create: `tests/test_catalog.py`

**Interfaces:**
- Consumes: `EntityType` from Task 2.
- Produces:
  - `Source` frozen dataclass: `id`, `name`, `accepts: tuple[EntityType, ...]`, `url`, `tags: tuple[str, ...]`, `notes: str | None`, `provenance: str | None`.
  - `load_catalog(directory: Path | None = None) -> tuple[Source, ...]`
  - `sources_for(catalog: tuple[Source, ...], entity_type: EntityType) -> tuple[Source, ...]`
  - `build_url(source: Source, value: str) -> str`
  - `CatalogError(Exception)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_catalog.py`:

```python
import pytest

from casefile.catalog import CatalogError, Source, build_url, load_catalog, sources_for
from casefile.types import EntityType


def test_loads_the_real_catalog():
    catalog = load_catalog()
    assert catalog
    assert all(isinstance(s, Source) for s in catalog)


def test_source_ids_are_unique_across_files():
    ids = [s.id for s in load_catalog()]
    assert len(ids) == len(set(ids)), f"duplicate ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_every_url_carries_the_value_placeholder():
    for source in load_catalog():
        assert "{value}" in source.url, f"{source.id} has no {{value}} in its url"


def test_every_url_is_https():
    """Blocks a contributed entry shipping javascript: or data: as a clickable link."""
    for source in load_catalog():
        assert source.url.startswith("https://"), f"{source.id} url is not https"


def test_non_https_scheme_is_rejected(tmp_path):
    (tmp_path / "evil.toml").write_bytes(
        b'[[source]]\nid = "x"\nname = "X"\naccepts = ["domain"]\nurl = "javascript:alert({value})"\n'
    )
    with pytest.raises(CatalogError, match="https"):
        load_catalog(tmp_path)


def test_every_accepts_entry_is_a_known_type():
    known = set(EntityType)
    for source in load_catalog():
        assert set(source.accepts) <= known, f"{source.id} accepts an unknown type"
        assert source.accepts, f"{source.id} accepts nothing"


def test_sources_for_filters_by_type():
    catalog = load_catalog()
    for source in sources_for(catalog, EntityType.DOMAIN):
        assert EntityType.DOMAIN in source.accepts


def test_build_url_percent_encodes_the_value():
    source = Source(id="x", name="X", accepts=(EntityType.COMPANY,), url="https://e.test/?q={value}")
    assert build_url(source, "Acme & Co/Ltd") == "https://e.test/?q=Acme%20%26%20Co%2FLtd"


def test_malformed_entry_raises_with_the_file_named(tmp_path):
    (tmp_path / "bad.toml").write_bytes(b'[[source]]\nid = "x"\n')
    with pytest.raises(CatalogError, match="bad.toml"):
        load_catalog(tmp_path)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_catalog.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.catalog'`

- [ ] **Step 3: Write `catalog.py`**

```python
"""TOML link catalogue: loading, validation, lookup and URL building."""

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from casefile.types import EntityType

PLACEHOLDER = "{value}"


class CatalogError(Exception):
    """A catalogue file is malformed. The message always names the file."""


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    name: str
    accepts: tuple[EntityType, ...]
    url: str
    tags: tuple[str, ...] = ()
    notes: str | None = None
    provenance: str | None = None


def _parse_source(raw: dict, origin: Path) -> Source:
    try:
        accepts = tuple(EntityType(a) for a in raw["accepts"])
        source = Source(
            id=raw["id"],
            name=raw["name"],
            accepts=accepts,
            url=raw["url"],
            tags=tuple(raw.get("tags", ())),
            notes=raw.get("notes"),
            provenance=raw.get("provenance"),
        )
    except (KeyError, ValueError) as exc:
        raise CatalogError(f"{origin.name}: invalid source entry {raw.get('id', '<no id>')}: {exc}") from exc
    if not source.url.startswith("https://"):
        raise CatalogError(f"{origin.name}: source {source.id} url must start with https://")
    if PLACEHOLDER not in source.url:
        raise CatalogError(f"{origin.name}: source {source.id} url has no {PLACEHOLDER}")
    if not source.accepts:
        raise CatalogError(f"{origin.name}: source {source.id} accepts nothing")
    return source


@lru_cache(maxsize=8)
def load_catalog(directory: Path | None = None) -> tuple[Source, ...]:
    """Cached: the web route calls this per request and the files never change at runtime."""
    directory = directory or Path(__file__).resolve().parent / "catalog"
    sources: list[Source] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.glob("*.toml")):
        with path.open("rb") as handle:
            try:
                document = tomllib.load(handle)
            except tomllib.TOMLDecodeError as exc:
                raise CatalogError(f"{path.name}: {exc}") from exc
        for raw in document.get("source", ()):
            source = _parse_source(raw, path)
            if source.id in seen:
                raise CatalogError(f"{path.name}: duplicate id {source.id}, already in {seen[source.id].name}")
            seen[source.id] = path
            sources.append(source)
    return tuple(sources)


def sources_for(catalog: tuple[Source, ...], entity_type: EntityType) -> tuple[Source, ...]:
    return tuple(s for s in catalog if entity_type in s.accepts)


def build_url(source: Source, value: str) -> str:
    return source.url.replace(PLACEHOLDER, quote(value, safe=""))
```

The https-only rule is a supply-chain guard, not pedantry. This repo invites catalogue
pull requests, and without it a single entry reading `url = "javascript:alert({value})"`
would render as a clickable link in every result page. Scheme is pinned at load time so a
bad entry fails CI rather than shipping.

- [ ] **Step 4: Write the first catalogue file**

Create `src/casefile/catalog/certificates.toml`:

```toml
# Certificate transparency and TLS inspection.

[[source]]
id = "crtsh"
name = "crt.sh"
accepts = ["domain"]
url = "https://crt.sh/?q={value}"
provenance = "awesome-osint"

[[source]]
id = "censys-certs"
name = "Censys Certificates"
accepts = ["domain"]
url = "https://search.censys.io/search?resource=hosts&q={value}"
provenance = "awesome-osint"

[[source]]
id = "certspotter"
name = "Cert Spotter"
accepts = ["domain"]
url = "https://sslmate.com/certspotter/api/v1/issuances?domain={value}"
notes = "public endpoint, rate limited"
provenance = "awesome-osint"
```

The catalogue lives **inside the package** at `src/casefile/catalog/`, not at the repo
root. One lookup path instead of a packaged-or-checkout branch, no `parents[2]` guess about
layout depth, and no `force-include` in `pyproject.toml`, because hatchling ships
non-Python files inside a package directory by default.

The cost is discoverability: contributors will not trip over it at the repo root. Paid for
by `CONTRIBUTING.md` naming the path and a one-line README pointer, both due in phase 2.

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_catalog.py -v`
Expected: PASS, 7 cases.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/catalog.py catalog/certificates.toml tests/test_catalog.py pyproject.toml
git commit -m "add catalogue dataclass, toml loader and url builder"
```

---

### Task 6: Seed the catalogue to 100+ type-slots

This task is data, not code. Its gate is Task 5's test suite plus the coverage test added here.

**Files:**
- Create: `src/casefile/catalog/domains.toml`, `src/casefile/catalog/network.toml`, `src/casefile/catalog/people.toml`, `src/casefile/catalog/companies.toml`, `src/casefile/catalog/crypto.toml`, `src/casefile/catalog/vehicles.toml`, `src/casefile/catalog/maritime.toml`, `src/casefile/catalog/aviation.toml`, `src/casefile/catalog/malware.toml`, `src/casefile/catalog/geo.toml`, `src/casefile/catalog/social.toml`
- Create: `tests/test_catalog_coverage.py`

**Interfaces:**
- Consumes: `load_catalog`, `sources_for` from Task 5.
- Produces: a catalogue meeting the per-type minimums below.

**Authoring procedure, per entry:**

1. Open the source in a browser.
2. Run a real search for a value of the type you are adding.
3. Copy the resulting URL from the address bar.
4. Replace the searched value with `{value}`.
5. Paste back into the browser with a different value to confirm the template works.
6. Add the entry with `provenance` naming where you found the tool.

Two to three minutes each. The allocation below is roughly four hours of work. Do not start it expecting fifteen minutes.

**Per-type slot minimums.** A source accepting three types fills three slots, so ~110 slots is ~70-80 unique entries.

| Type | Slots | Type | Slots | Type | Slots |
|---|---|---|---|---|---|
| `domain` | 12 | `url` | 5 | `mac` | 3 |
| `ip` | 10 | `cve` | 4 | `vin` | 3 |
| `email` | 8 | `asn` | 4 | | |
| `person` | 8 | `btc_address` | 4 | `mmsi` | 3 |
| `company` | 8 | `coordinates` | 4 | `imo` | 3 |
| `phone` | 5 | `eth_address` | 3 | `icao24` | 3 |
| `hash` | 5 | | | `tail_number` | 3 |

Two types have no minimum. `username` because WhatsMyName supplies 700 sites in phase 4; add username link entries only where a site is worth a direct pivot regardless. `plate` because nothing detects it in v1, so its entries would be unreachable.

- [ ] **Step 1: Write the failing coverage test**

Create `tests/test_catalog_coverage.py`:

```python
from casefile.catalog import load_catalog, sources_for
from casefile.types import EntityType

MINIMUM_SLOTS = 100
FLOOR_PER_TYPE = 3
EXEMPT = {EntityType.USERNAME, EntityType.PLATE}  # WMN covers username; nothing detects plate in v1


def test_every_type_has_a_floor_of_sources():
    catalog = load_catalog()
    thin = {
        t.value: len(sources_for(catalog, t))
        for t in EntityType
        if t not in EXEMPT and len(sources_for(catalog, t)) < FLOOR_PER_TYPE
    }
    assert not thin, f"types below {FLOOR_PER_TYPE} sources: {thin}"


def test_total_slot_coverage():
    catalog = load_catalog()
    slots = sum(len(s.accepts) for s in catalog)
    assert slots >= MINIMUM_SLOTS, f"{slots} slots, need {MINIMUM_SLOTS}"

```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_catalog_coverage.py -v`
Expected: FAIL. `test_every_type_has_a_floor_of_sources` lists every type at zero except `domain`.

- [ ] **Step 3: Author the catalogue files**

Work type by type, committing per file so progress is durable. Worked examples of the three shapes you will meet:

```toml
# src/casefile/catalog/network.toml: a source accepting several types fills several slots
[[source]]
id = "shodan"
name = "Shodan"
accepts = ["ip", "domain", "asn"]
url = "https://www.shodan.io/search?query={value}"
provenance = "awesome-osint"

# src/casefile/catalog/companies.toml: a value that is not the last path segment
[[source]]
id = "opencorporates"
name = "OpenCorporates"
accepts = ["company"]
url = "https://opencorporates.com/companies?q={value}&utf8=%E2%9C%93"
provenance = "awesome-osint"

# src/casefile/catalog/maritime.toml: a site needing a note about its limits
[[source]]
id = "marinetraffic"
name = "MarineTraffic"
accepts = ["mmsi", "imo"]
url = "https://www.marinetraffic.com/en/ais/index/search/all?keyword={value}"
notes = "throttles anonymous search hard"
provenance = "awesome-osint"
```

- [ ] **Step 4: Run both catalogue suites to verify they pass**

Run: `uv run pytest tests/test_catalog.py tests/test_catalog_coverage.py -v`
Expected: all PASS. If a type is still thin, the failure message names it.

- [ ] **Step 5: Commit**

Commit per category file as you go, then:

```bash
git add catalog tests/test_catalog_coverage.py
git commit -m "seed catalogue to 100 type-slots across all 21 types"
```

---

### Task 7: Result model, CLI text and JSON output

**Files:**
- Create: `src/casefile/report.py`
- Create: `tests/test_report.py`
- Modify: `src/casefile/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `build_report`, `Section` from `report.py`.
- Produces: `main(argv: list[str] | None = None) -> int`. The renderers are private; `main` is the only caller.

- [ ] **Step 1: Write the failing test for the result model**

Create `tests/test_report.py`:

```python
from casefile.report import build_report


def test_sections_follow_detection_order():
    sections = build_report("example.com")
    assert [s.type for s in sections] == ["domain", "username", "person", "company"]


def test_links_carry_encoded_urls():
    (section,) = [s for s in build_report("example.com") if s.type == "domain"]
    crtsh = next(link for link in section.links if link.id == "crtsh")
    assert crtsh.url == "https://crt.sh/?q=example.com"


def test_unrecognised_input_yields_no_sections():
    assert build_report("!!!") == ()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.report'`

- [ ] **Step 3: Write `report.py`**

```python
"""The result shape. One builder, three renderers: text, JSON and HTML."""

from dataclasses import dataclass

from casefile.catalog import build_url, load_catalog, sources_for
from casefile.detect import detect


@dataclass(frozen=True)
class Link:
    id: str
    name: str
    url: str
    notes: str | None = None


@dataclass(frozen=True)
class Section:
    type: str
    value: str
    links: tuple[Link, ...]


def build_report(raw: str) -> tuple[Section, ...]:
    catalog = load_catalog()
    return tuple(
        Section(
            type=candidate.type.value,
            value=candidate.value,
            links=tuple(
                Link(s.id, s.name, build_url(s, candidate.value), s.notes)
                for s in sources_for(catalog, candidate.type)
            ),
        )
        for candidate in detect(raw)
    )
```

This exists so the CLI and the web app cannot drift. Both render the same `Section` tuple,
which makes "the demo is a prerender of the real app" structurally true rather than a thing
we remember to keep true.

- [ ] **Step 4: Write the failing CLI test**

Create `tests/test_cli.py`:

```python
import json

from casefile.cli import main


def test_text_output_lists_types_and_links(capsys):
    assert main(["example.com"]) == 0
    out = capsys.readouterr().out
    assert "domain" in out
    assert "crt.sh" in out
    assert "https://crt.sh/?q=example.com" in out


def test_json_output_is_valid_and_structured(capsys):
    assert main(["example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"] == "example.com"
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert domain["value"] == "example.com"
    assert any(link["id"] == "crtsh" for link in domain["links"])


def test_unrecognised_input_exits_nonzero(capsys):
    assert main(["   "]) == 1
    assert "nothing recognised" in capsys.readouterr().err


def test_only_one_positional_value_is_accepted():
    import pytest

    with pytest.raises(SystemExit):
        main(["one.example", "two.example"])
```

- [ ] **Step 5: Run it to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL. The placeholder `main()` takes no arguments.

- [ ] **Step 6: Rewrite `cli.py`**

```python
"""argparse entry point: print results, emit JSON, or launch the local web app."""

import argparse
import json
import sys
from dataclasses import asdict

from casefile import __version__
from casefile.report import Section, build_report

REPO = "https://github.com/cpwillis/casefile"


def _render_text(raw: str, sections: tuple[Section, ...]) -> str:
    lines = [raw]
    for index, section in enumerate(sections):
        marker = "most likely" if index == 0 else ""
        lines.append("")
        lines.append(f"  {section.type.upper():<14} {section.value:<40} {marker}")
        if not section.links:
            lines.append("    no sources")
        for link in section.links:
            lines.append(f"    {link.name:<28} {link.url}")
    return "\n".join(lines)


def _render_json(raw: str, sections: tuple[Section, ...]) -> str:
    return json.dumps({"input": raw, "candidates": [asdict(s) for s in sections]}, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casefile",
        description="One input box, every relevant OSINT pivot. Runs locally.",
        epilog=f"Exactly one target per run, by design. {REPO}",
    )
    parser.add_argument("value", nargs="?", help="the identifier to look up")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--port", type=int, default=8765, help="port for the web app (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser on launch")
    parser.add_argument("--version", action="version", version=f"casefile {__version__}")
    args = parser.parse_args(argv)

    if args.value is None:
        from casefile.web.app import serve

        return serve(port=args.port, open_browser=not args.no_browser)

    sections = build_report(args.value)
    if not sections:
        print(f"nothing recognised in {args.value!r}", file=sys.stderr)
        return 1

    render = _render_json if args.json else _render_text
    print(render(args.value, sections))
    return 0
```

- [ ] **Step 7: Run both modules to verify they pass**

Run: `uv run pytest tests/test_report.py tests/test_cli.py -v`
Expected: all PASS. `test_only_one_positional_value_is_accepted` passes because argparse rejects the extra positional.

The web import sits inside the branch that needs it so `casefile <value>` never imports Starlette.

- [ ] **Step 8: Commit**

```bash
git add src/casefile/report.py src/casefile/cli.py tests/test_report.py tests/test_cli.py
git commit -m "add result model, cli text and json output"
```

---

### Task 8: Starlette app and index page

**Files:**
- Create: `src/casefile/web/__init__.py`, `src/casefile/web/app.py`
- Create: `src/casefile/web/templates/base.html`, `index.html`
- Create: `src/casefile/web/static/casefile.css`
- Create: `tests/test_web.py`
- Modify: `pyproject.toml` (add `starlette`, `uvicorn`, `jinja2`)

**Interfaces:**
- Consumes: `build_report` from `report.py`.
- Produces: `app` (Starlette instance), `serve(port: int, host: str = "127.0.0.1", open_browser: bool = True) -> int`.

- [ ] **Step 1: Add the dependencies**

In `pyproject.toml`, replace `dependencies = []` with:

```toml
dependencies = [
  "starlette>=0.41",
  "uvicorn>=0.32",
  "jinja2>=3.1",
]
```

Run: `uv sync`

- [ ] **Step 2: Write the failing test**

Create `tests/test_web.py`:

```python
from starlette.testclient import TestClient

from casefile.web.app import app

client = TestClient(app)


def test_index_renders_a_search_form():
    response = client.get("/")
    assert response.status_code == 200
    assert "<form" in response.text
    assert 'name="v"' in response.text



def test_search_input_is_labelled():
    text = client.get("/").text
    assert 'for="target"' in text
    assert 'id="target"' in text


def test_index_has_a_heading_and_skip_link():
    text = client.get("/").text
    assert "<h1" in text
    assert 'class="skip"' in text


def test_query_is_escaped_not_injected():
    payload = "<script>alert(1)</script>"
    text = client.get("/q", params={"v": payload}).text
    assert payload not in text
    assert "&lt;script&gt;" in text


def test_serve_defaults_to_loopback():
    import inspect

    from casefile.web.app import serve

    assert inspect.signature(serve).parameters["host"].default == "127.0.0.1"
```

`TestClient` needs `httpx`, which arrives in phase 3. Add it to the dev group for now: `dev = ["pytest>=8.3", "ruff>=0.8", "httpx>=0.28"]`.

- [ ] **Step 3: Run it to verify it fails**

Run: `uv run pytest tests/test_web.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.web'`

- [ ] **Step 4: Create the package and asset directories**

```bash
mkdir -p src/casefile/web/templates src/casefile/web/static
echo '# Local web app. Loopback only.' > src/casefile/web/__init__.py
```

`web/__init__.py` must exist rather than relying on namespace packages, because
`[tool.hatch.build.targets.wheel] packages = ["src/casefile"]` walks real packages when
building the wheel.

- [ ] **Step 5: Write `app.py`**

```python
"""Starlette app. Binds loopback only; this is a local tool, not a service."""

import threading
import webbrowser
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from casefile.report import build_report

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")


async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return templates.TemplateResponse(request, "index.html")
    sections = build_report(raw)
    return templates.TemplateResponse(request, "result.html", {"raw": raw, "sections": sections})


app = Starlette(
    routes=[
        Route("/", index),
        Route("/q", result),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ]
)


def serve(port: int = 8765, host: str = "127.0.0.1", open_browser: bool = True) -> int:
    url = f"http://{host}:{port}"
    print(f"casefile is running at {url}")
    print("press ctrl-c to stop")
    if open_browser:
        # ponytail: fixed 0.5s delay rather than a uvicorn startup hook, so tests that exercise
        # `app` can never launch a browser. Raise it if a cold browser ever races the bind.
        threading.Timer(0.5, webbrowser.open, [url]).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
```

- [ ] **Step 6: Write `base.html`**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}casefile{% endblock %}</title>
<link rel="stylesheet" href="/static/casefile.css">
</head>
<body>
<a class="skip" href="#pane">Skip to results</a>
<header class="topbar">
  <form action="/q" method="get" class="search" role="search">
    <label class="visually-hidden" for="target">Identifier to look up</label>
    <input id="target" type="search" name="v" value="{{ raw | default('') }}"
           placeholder="domain, ip, email, username, company, hash…" autofocus>
    <button type="submit">Search</button>
  </form>
</header>
{% block content %}{% endblock %}
</body>
</html>
```

- [ ] **Step 7: Write `index.html`**

```html
{% extends "base.html" %}
{% block content %}
<main class="intro" id="pane">
  <h1 class="visually-hidden">casefile</h1>
  <p>Paste any identifier. casefile works out what it could be, then shows every relevant public source.</p>
  <p class="muted">Runs entirely on this machine. Requests go out over your own connection.</p>
</main>
{% endblock %}
```

- [ ] **Step 8: Write a minimal `casefile.css`**

```css
:root { --fg: #1a1a1a; --bg: #fdfdfc; --muted: #6b6b6b; --line: #e0dedb; --accent: #2d5f8a; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e8e6e3; --bg: #1c1c1a; --muted: #9a9895; --line: #34332f; --accent: #7fb3d9; }
}
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; color: var(--fg); background: var(--bg); }
a { color: var(--accent); }
.muted { color: var(--muted); }
.topbar { border-bottom: 1px solid var(--line); padding: 12px 16px; }
.search { display: flex; gap: 8px; max-width: 1200px; margin: 0 auto; }
.search input, .search button { border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--fg); }
.search input { flex: 1; padding: 8px 10px; }
.search button { padding: 8px 16px; cursor: pointer; }
.intro { max-width: 640px; margin: 15vh auto; padding: 0 16px; }
.visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.skip { position: absolute; left: -9999px; }
.skip:focus { left: 8px; top: 8px; z-index: 1; background: var(--bg); padding: 8px; border: 1px solid var(--line); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `uv run pytest tests/test_web.py -v`
Expected: both PASS.

- [ ] **Step 10: Commit**

```bash
git add src/casefile/web tests/test_web.py pyproject.toml
git commit -m "add starlette app, base template and index page"
```

---

### Task 9: Result page with rail and pane

Implements the layout recorded in the spec under Result page layout: sticky rail, anchor-link navigation, links inline per type.

**Files:**
- Create: `src/casefile/web/templates/result.html`
- Modify: `src/casefile/web/static/casefile.css`
- Modify: `tests/test_web.py`

**Interfaces:**
- Consumes: the `sections` context from Task 8's `result` route.
- Produces: rendered HTML with `id="type-<type>"` anchors the rail links to.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_web.py`:

```python
def test_result_page_renders_rail_and_pane():
    response = client.get("/q", params={"v": "example.com"})
    assert response.status_code == 200
    assert 'class="rail"' in response.text
    assert 'id="type-domain"' in response.text
    assert 'href="#type-domain"' in response.text


def test_result_page_lists_links_with_encoded_values():
    text = client.get("/q", params={"v": "Acme & Co"}).text
    assert "Acme%20%26%20Co" in text


def test_domain_section_precedes_company_section():
    text = client.get("/q", params={"v": "example.com"}).text
    assert text.index('id="type-domain"') < text.index('id="type-company"')


def test_blank_query_falls_back_to_index():
    assert "<form" in client.get("/q", params={"v": "  "}).text


def test_unrecognised_input_says_so():
    assert "nothing recognised" in client.get("/q", params={"v": "!!!"}).text.lower()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_web.py -v`
Expected: FAIL, `result.html` does not exist.

- [ ] **Step 3: Write `result.html`**

```html
{% extends "base.html" %}
{% block title %}{{ raw }} · casefile{% endblock %}
{% block content %}
{% if not sections %}
<main class="intro"><p>Nothing recognised in <code>{{ raw }}</code>.</p></main>
{% else %}
<h1 class="visually-hidden">casefile results for {{ raw }}</h1>
<div class="layout">
  <nav class="rail" aria-label="Readings and sources">
    {% for section in sections %}
    <div class="rail-block">
      <a class="rail-type" href="#type-{{ section.type }}">{{ section.type }}</a>
      <a class="rail-links" href="#links-{{ section.type }}">{{ section.links | length }} links</a>
    </div>
    {% endfor %}
    <p class="rail-tally muted">{{ sections | length }} reading{{ 's' if sections | length != 1 }}</p>
  </nav>

  <main class="pane" id="pane">
    {% for section in sections %}
    <section class="type-section" id="type-{{ section.type }}">
      <h2>{{ section.type }}
        <span class="muted">{{ section.value }}</span>
        {% if loop.first %}<span class="tag">most likely</span>{% endif %}
      </h2>

      <h3 id="links-{{ section.type }}">Links ({{ section.links | length }})</h3>
      <label class="visually-hidden" for="filter-{{ section.type }}">Filter {{ section.type }} links</label>
      <input class="filter" id="filter-{{ section.type }}" type="search" placeholder="filter links…"
             data-filters="links-{{ section.type }}-list">
      <ul class="links" id="links-{{ section.type }}-list">
        {% for link in section.links %}
        <li><a href="{{ link.url }}" rel="noreferrer noopener" target="_blank">{{ link.name }}</a>
          {% if link.notes %}<span class="muted">{{ link.notes }}</span>{% endif %}
        </li>
        {% else %}
        <li class="muted">no sources for this type yet</li>
        {% endfor %}
      </ul>
    </section>
    {% endfor %}
  </main>
</div>
{% endif %}
{% endblock %}
```

`target="_blank"` with `rel="noreferrer"` matters here: it stops the target site seeing casefile's page as the referrer.

The filter uses the `hidden` attribute rather than `display: none` in a class, so filtered-out
links leave the accessibility tree as well as the layout.

- [ ] **Step 4: Add the layout CSS**

Append to `casefile.css`:

```css
.layout { display: grid; grid-template-columns: 220px 1fr; gap: 24px; max-width: 1200px; margin: 0 auto; padding: 16px; }
.rail { position: sticky; top: 16px; align-self: start; font-size: 13px; }
.rail-block { margin-bottom: 14px; }
.rail-type { display: block; text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
.rail-links { display: block; color: var(--muted); }
.rail-tally { border-top: 1px solid var(--line); padding-top: 10px; }
.type-section { margin-bottom: 40px; scroll-margin-top: 16px; }
.type-section h2 { text-transform: uppercase; letter-spacing: .04em; font-size: 15px; }
.tag { font-size: 11px; border: 1px solid var(--line); border-radius: 3px; padding: 1px 6px; color: var(--muted); text-transform: none; letter-spacing: 0; }
.filter { width: 100%; max-width: 320px; padding: 6px 8px; margin-bottom: 10px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--fg); }
.links { list-style: none; padding: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 6px 16px; }
.links li[hidden] { display: none; }

@media (max-width: 900px) {
  .layout { grid-template-columns: 1fr; }
  .rail { position: static; display: flex; flex-wrap: wrap; gap: 12px; border-bottom: 1px solid var(--line); padding-bottom: 10px; }
  .rail-block { margin: 0; }
  .rail-tally { border: 0; padding: 0; }
}
```

The 900px query is the whole of the collapse. The pane already holds everything in reading order, so nothing else changes.

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_web.py -v`
Expected: all seven PASS.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/web tests/test_web.py
git commit -m "add result page with rail and pane layout"
```

---

### Task 10: Link filter, constraint tests, and launch

**Files:**
- Create: `src/casefile/web/static/casefile.js`
- Modify: `src/casefile/web/templates/base.html`
- Create: `tests/test_constraints.py`

**Interfaces:**
- Consumes: everything above.
- Produces: a verified `0.1.0` candidate.

- [ ] **Step 1: Write the acceptance test**

Create `tests/test_constraints.py`:

```python
"""Tests that defend decisions rather than behaviour. A failure here is a reversal."""

from pathlib import Path

from starlette.testclient import TestClient

from casefile.detect import detect
from casefile.web.app import app


def test_cli_and_web_render_the_same_readings():
    """The demo is a prerender of the web app, so the two must never diverge."""
    text = TestClient(app).get("/q", params={"v": "example.com"}).text
    for candidate in detect("example.com"):
        assert f'id="type-{candidate.type.value}"' in text


def test_app_has_no_startup_hooks():
    """A browser-opening startup hook would fire under TestClient and launch a browser in CI."""
    assert app.router.on_startup == []


def test_no_network_dependency_in_this_phase():
    """Phase 1 must not import httpx anywhere in the package."""
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    offenders = [p.name for p in package.rglob("*.py") if "import httpx" in p.read_text()]
    assert not offenders, f"httpx imported in phase 1: {offenders}"
```

Two tests, not four. The draft also asserted that the CLI prints ranked types with links
and that the catalogue meets the slot bar, both of which are already covered verbatim by
`test_cli.py` and `test_catalog_coverage.py`. An acceptance module that restates module
tests inflates the count and doubles the maintenance without adding a single new way to
fail.

- [ ] **Step 2: Run it to see what is missing**

Run: `uv run pytest tests/test_constraints.py -v`
Expected: PASS if Tasks 1-9 are complete. Any failure names the gap.

- [ ] **Step 3: Write the link filter**

Create `src/casefile/web/static/casefile.js`:

```javascript
// The only JavaScript in casefile. Filtering links; nothing else needs it.
document.addEventListener("input", (event) => {
  const input = event.target.closest(".filter");
  if (!input) return;
  const list = document.getElementById(input.dataset.filters);
  if (!list) return;
  const needle = input.value.trim().toLowerCase();
  for (const item of list.children) {
    item.hidden = needle !== "" && !item.textContent.toLowerCase().includes(needle);
  }
});
```

- [ ] **Step 4: Load it from `base.html`**

Add before `</body>`:

```html
<script src="/static/casefile.js" defer></script>
```

- [ ] **Step 5: Verify the app by hand**

Run: `uv run casefile`

Confirm it prints the URL and your browser opens on it unprompted. Then search
`example.com` and confirm: the rail lists both readings, clicking a rail entry scrolls to that section, the filter narrows the link list, and narrowing the window below 900px collapses the rail to a strip.

- [ ] **Step 6: Run everything**

Run: `uv run ruff check && uv run ruff format --check && uv run pytest -q`
Expected: all pass.

- [ ] **Step 7: Set the version and commit**

Set `version = "0.1.0"` in `pyproject.toml` and `__version__ = "0.1.0"` in `src/casefile/__init__.py`.

```bash
git add -A
git commit -m "add link filter and phase 1 acceptance tests, bump to 0.1.0"
```

Do not tag or push. The repo owner does both.

---

## Notes for the executor

- **Never `git push`.** Commit locally only.
- **Never `--no-gpg-sign`.** If signing prompts for a passphrase, stop and hand back.
- **No em dashes** in any prose you write, including comments and docstrings.
- Comments and docstrings are one tight line up to 120 characters. Prefer one line over a paragraph.
- If a task tempts you toward an abstraction with one caller, don't. That is what the audit already removed once.
