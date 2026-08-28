# casefile Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `0.3.0`: result panels that fetch live data from three keyless sources (DNS-over-HTTPS, RDAP, crt.sh), each panel loading itself in the browser and rendering one of six honest states.

**Architecture:** The browser is the orchestrator. Each fetchable source gets an empty `<div hx-get="/panel/{id}" hx-trigger="load">` that self-loads via HTMX; the server endpoint is stateless and handles exactly one source. A `@fetcher` registry maps source ids to async functions; a shared rate limiter and HTTP client wrap every outbound request with a User-Agent, timeouts, one retry, and concurrency caps. Fetcher failures are contained to a single dead panel.

**Tech Stack:** Python 3.12, httpx (async), Starlette, HTMX (vendored), stdlib `asyncio`/`random`/`time`. Ruff and pytest for dev; `httpx.MockTransport` for hermetic fetcher tests.

**Spec:** [docs/superpowers/specs/2026-08-27-casefile-design.md](../specs/2026-08-27-casefile-design.md)

**Master plan:** [docs/superpowers/plans/2026-08-27-casefile-master-plan.md](2026-08-27-casefile-master-plan.md)

**Depends on:** Phase 1 (complete). Independent of Phase 2.

## Global Constraints

- Python `>=3.12`.
- Runtime dependencies after this phase: `httpx`, `starlette`, `uvicorn`, `jinja2`. That is four of the project's five-dep budget; `phonenumbers` is the fifth and arrives in phase 4. **No sixth dependency.** HTMX is a vendored static asset, not a Python dependency.
- Each dependency is added to `pyproject.toml` by the task that first imports it. This phase promotes `httpx` from the dev group to runtime.
- **The SQLite cache is NOT in this phase.** It is phase 4. The spec's "Cache: added in phase 3" line predates the resequence; ignore it.
- Rate limiting, exact values from the spec: global concurrency **20**, per-domain **4**, jitter **0 to 250 ms** before each request.
- Timeouts: **5 s connect, 20 s read**. **One** retry on 429 or 5xx with exponential backoff, then give up. Never more than one retry.
- Every outbound request sends `User-Agent: casefile/<version> (+https://github.com/cpwillis/casefile)`. Never spoof a browser UA.
- Six panel states, exact names: `ok`, `empty`, `needs_key`, `rate_limited`, `timeout`, `error`. `empty` and `error` must render differently.
- A dead source renders as a dead panel, never a failed page.
- Web app binds `127.0.0.1` only. Findings from third-party APIs are untrusted; every template that renders them must autoescape (Jinja `.html` templates do by default).
- Hermetic tests never touch the network. Live tests are marked `live` and excluded by default.
- Commits are bare lowercase one-line, linear, GPG-signed. No `--no-gpg-sign`. Never push.

## File Structure

| File | Responsibility |
|---|---|
| `src/casefile/fetchers/__init__.py` | `Finding`, `SourceResult`, `State`, exceptions, the `@fetcher` registry, and `run_fetcher()`. The whole fetch contract in one focused module. |
| `src/casefile/fetchers/http.py` | Shared `AsyncClient` factory (User-Agent, timeouts) and the rate limiter. |
| `src/casefile/fetchers/sources.py` | The three concrete fetchers: `dns`, `rdap`, `crtsh`. |
| `src/casefile/web/app.py` | Adds the `/panel/{source_id}` route. |
| `src/casefile/web/templates/panel.html` | One partial rendering a `SourceResult` by state. |
| `src/casefile/web/templates/result.html` | Adds a self-loading panel div per registered fetcher. |
| `src/casefile/web/static/htmx.min.js` | Vendored HTMX (pinned). |
| `src/casefile/web/static/casefile.css` | Panel and state styling. |
| `src/casefile/report.py` | Gains `links_for(candidate)`, the one place per-candidate link URLs are built, reused by the web route, the CLI and `build_report`. |
| `src/casefile/cli.py` | Fans out fetchers with `asyncio.gather`; adds `--no-fetch`. |
| `.github/workflows/live.yml` | Manual `workflow_dispatch` run of the `live` tests. |
| `tests/test_fetchers.py`, `tests/test_http.py`, `tests/test_sources.py`, `tests/test_panels.py`, `tests/test_live_sources.py` | One module per source module; live tests isolated. |

Why `fetchers/` is a package, not one file: the registry/contract, the HTTP plumbing, and the concrete sources change for different reasons and at different rates. Concrete sources will grow to a dozen files in phase 4; keeping them out of the contract module keeps each readable.

---

### Task 1: Promote httpx, vendor HTMX, retire the no-network constraint

**Files:**
- Modify: `pyproject.toml`
- Create: `src/casefile/web/static/htmx.min.js`
- Modify: `src/casefile/web/templates/base.html`
- Modify: `tests/test_constraints.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `httpx` importable in `src/`; HTMX loaded on every page.

- [ ] **Step 1: Move httpx to runtime deps**

In `pyproject.toml`, change the dependencies block to:

```toml
dependencies = [
  "httpx>=0.28",
  "starlette>=0.41",
  "uvicorn>=0.32",
  "jinja2>=3.1",
]
```

And drop `httpx` from the dev group (it is now pulled in transitively):

```toml
dev = ["pytest>=8.3", "ruff>=0.8"]
```

Run: `uv sync`

- [ ] **Step 2: Vendor HTMX**

HTMX must be served locally: the phase-2 demo runs under a strict CSP that blocks CDNs, and casefile is meant to work offline. Pin a version:

```bash
curl -L https://unpkg.com/htmx.org@2.0.6/dist/htmx.min.js -o src/casefile/web/static/htmx.min.js
```

Verify it downloaded (non-empty, starts with a comment or `(function`):

```bash
head -c 60 src/casefile/web/static/htmx.min.js; echo
```

If the download is empty or an HTML error page, stop and fix before continuing.

- [ ] **Step 3: Load HTMX from base.html**

In `src/casefile/web/templates/base.html`, add before the existing `casefile.js` script tag:

```html
<script src="/static/htmx.min.js" defer></script>
```

- [ ] **Step 4: Replace the no-network constraint test**

The phase-1 constraint `test_no_network_dependency_in_this_phase` asserted `httpx` was imported nowhere in `src/`. That is now false by design. Open `tests/test_constraints.py` and replace that test with one that enforces the real remaining rule: all outbound HTTP goes through the shared client, so `httpx.AsyncClient(` is constructed in exactly one place.

```python
def test_async_client_is_constructed_in_one_place():
    """Every fetcher must use the shared client so the User-Agent and timeouts are uniform."""
    package = Path(__file__).resolve().parents[1] / "src" / "casefile"
    offenders = [
        p.relative_to(package).as_posix()
        for p in package.rglob("*.py")
        if "httpx.AsyncClient(" in p.read_text() and p.name != "http.py"
    ]
    assert offenders == [], f"AsyncClient built outside fetchers/http.py: {offenders}"
```

- [ ] **Step 5: Run the constraint tests**

Run: `uv run pytest tests/test_constraints.py -v`
Expected: PASS (no `httpx.AsyncClient(` exists yet, so the offender list is empty).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/casefile/web/static/htmx.min.js src/casefile/web/templates/base.html tests/test_constraints.py
git commit -m "promote httpx to runtime, vendor htmx, retire no-network constraint"
```

---

### Task 2: Result model, states and exceptions

**Files:**
- Create: `src/casefile/fetchers/__init__.py`
- Create: `tests/test_fetchers.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Finding(label: str, value: str, url: str | None = None)` frozen dataclass.
  - `SourceResult(source_id: str, state: str, findings: tuple[Finding, ...] = (), detail: str | None = None, elapsed_ms: int = 0)` frozen dataclass.
  - `class State`: string constants `OK = "ok"`, `EMPTY = "empty"`, `NEEDS_KEY = "needs_key"`, `RATE_LIMITED = "rate_limited"`, `TIMEOUT = "timeout"`, `ERROR = "error"`.
  - `class NeedsKey(Exception)`, `class RateLimited(Exception)` — fetchers raise these; `run_fetcher` (Task 5) maps them to states.

- [ ] **Step 1: Write the failing test**

Create `tests/test_fetchers.py`:

```python
from casefile.fetchers import Finding, NeedsKey, RateLimited, SourceResult, State


def test_state_names_are_exact():
    assert (State.OK, State.EMPTY, State.NEEDS_KEY, State.RATE_LIMITED, State.TIMEOUT, State.ERROR) == (
        "ok",
        "empty",
        "needs_key",
        "rate_limited",
        "timeout",
        "error",
    )


def test_finding_defaults_url_to_none():
    assert Finding(label="A", value="1").url is None


def test_source_result_is_flat_and_defaults_empty():
    r = SourceResult(source_id="x", state=State.EMPTY)
    assert r.findings == ()
    assert r.detail is None
    assert r.elapsed_ms == 0


def test_exceptions_exist():
    assert issubclass(NeedsKey, Exception)
    assert issubclass(RateLimited, Exception)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_fetchers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.fetchers'`

- [ ] **Step 3: Write the model**

Create `src/casefile/fetchers/__init__.py`:

```python
"""Fetcher contract: the result model, panel states, exceptions, registry and runner."""

from dataclasses import dataclass


class State:
    OK = "ok"
    EMPTY = "empty"
    NEEDS_KEY = "needs_key"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"


class NeedsKey(Exception):
    """A fetcher raises this when a required key is not configured."""


class RateLimited(Exception):
    """Raised when a source returns 429 after the single retry is exhausted."""


@dataclass(frozen=True)
class Finding:
    label: str
    value: str
    url: str | None = None


@dataclass(frozen=True)
class SourceResult:
    source_id: str
    state: str
    findings: tuple[Finding, ...] = ()
    detail: str | None = None  # error reason, or a note on the state
    elapsed_ms: int = 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_fetchers.py -v`
Expected: PASS, 4 cases.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/__init__.py tests/test_fetchers.py
git commit -m "add fetcher result model, states and exceptions"
```

---

### Task 3: The @fetcher registry

**Files:**
- Modify: `src/casefile/fetchers/__init__.py`
- Modify: `tests/test_fetchers.py`

**Interfaces:**
- Consumes: `EntityType` from `casefile.types`.
- Produces:
  - `@fetcher(id: str, accepts: list[EntityType])` decorator registering an async function `f(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]`.
  - `registered_fetcher(source_id: str) -> Registered | None` returning the registered record (or None).
  - `Registered` frozen dataclass: `id: str`, `accepts: tuple[EntityType, ...]`, `func: Callable`.
  - `has_fetcher(source_id: str) -> bool`.
  - `fetchers_for(entity_type: EntityType) -> tuple[str, ...]` returning the ids of fetchers accepting that type.

Note on the signature: the spec sketches `f(value, client)`. This plan passes `entity_type` too, so one fetcher can serve several types (DNS serves `domain` and `email`). That is the only deviation from the sketch, and it is deliberate.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fetchers.py`:

```python
import pytest

from casefile.fetchers import fetcher, fetchers_for, has_fetcher, registered_fetcher
from casefile.types import EntityType


def test_register_and_look_up_a_fetcher():
    @fetcher(id="probe", accepts=[EntityType.DOMAIN, EntityType.EMAIL])
    async def probe(value, entity_type, client):
        return []

    rec = registered_fetcher("probe")
    assert rec is not None
    assert rec.id == "probe"
    assert rec.accepts == (EntityType.DOMAIN, EntityType.EMAIL)
    assert rec.func is probe
    assert has_fetcher("probe")
    assert "probe" in fetchers_for(EntityType.DOMAIN)
    assert "probe" not in fetchers_for(EntityType.IP)


def test_unknown_id_returns_none():
    assert registered_fetcher("nope") is None
    assert not has_fetcher("nope")


def test_duplicate_id_is_rejected():
    @fetcher(id="dupe", accepts=[EntityType.IP])
    async def a(value, entity_type, client):
        return []

    with pytest.raises(ValueError, match="dupe"):

        @fetcher(id="dupe", accepts=[EntityType.IP])
        async def b(value, entity_type, client):
            return []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_fetchers.py -k registry -v` (or run the whole module)
Expected: FAIL with `ImportError: cannot import name 'fetcher'`

- [ ] **Step 3: Add the registry**

Append to `src/casefile/fetchers/__init__.py` (add `from collections.abc import Callable` and `from casefile.types import EntityType` to the imports):

```python
@dataclass(frozen=True)
class Registered:
    id: str
    accepts: tuple[EntityType, ...]
    func: Callable


_REGISTRY: dict[str, Registered] = {}


def fetcher(id: str, accepts: list[EntityType]):
    def register(func: Callable) -> Callable:
        if id in _REGISTRY:
            raise ValueError(f"duplicate fetcher id {id}")
        _REGISTRY[id] = Registered(id=id, accepts=tuple(accepts), func=func)
        return func

    return register


def registered_fetcher(source_id: str) -> Registered | None:
    return _REGISTRY.get(source_id)


def has_fetcher(source_id: str) -> bool:
    return source_id in _REGISTRY


def fetchers_for(entity_type: EntityType) -> tuple[str, ...]:
    return tuple(r.id for r in _REGISTRY.values() if entity_type in r.accepts)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_fetchers.py -v`
Expected: PASS.

Note for later tasks: the real fetchers in Task 6 register at import time, so any code needing the registry populated must `import casefile.fetchers.sources` first. Task 6 documents where that import lives.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/__init__.py tests/test_fetchers.py
git commit -m "add fetcher registry decorator and lookups"
```

---

### Task 4: HTTP client factory and rate limiter

**Files:**
- Create: `src/casefile/fetchers/http.py`
- Create: `tests/test_http.py`

**Interfaces:**
- Consumes: `__version__` from `casefile`.
- Produces:
  - `USER_AGENT: str` = `f"casefile/{__version__} (+https://github.com/cpwillis/casefile)"`.
  - `build_client() -> httpx.AsyncClient` with the User-Agent header, `httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=20.0)`, and `follow_redirects=True`.
  - `async with domain_slot(host: str):` an async context manager acquiring the global (20) and per-host (4) semaphores and sleeping a 0-250 ms jitter before yielding.
  - `async def get_json(client, url, host) -> httpx.Response` performing the GET inside `domain_slot`, with one retry on 429/5xx, raising `RateLimited` if the retry is still 429 and re-raising other errors.

- [ ] **Step 1: Write the failing test**

Create `tests/test_http.py`:

```python
import asyncio

import httpx
import pytest

from casefile.fetchers import RateLimited
from casefile.fetchers.http import USER_AGENT, build_client, domain_slot, get_json


def test_user_agent_names_the_project_and_version():
    assert USER_AGENT.startswith("casefile/")
    assert "github.com/cpwillis/casefile" in USER_AGENT


def test_build_client_sets_the_user_agent_and_timeouts():
    client = build_client()
    assert client.headers["user-agent"] == USER_AGENT
    assert client.timeout.connect == 5.0
    assert client.timeout.read == 20.0


async def test_domain_slot_caps_concurrency_per_host():
    active = 0
    peak = 0

    async def worker():
        nonlocal active, peak
        async with domain_slot("h.test"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(*(worker() for _ in range(12)))
    assert peak <= 4  # per-host cap


async def test_get_json_retries_once_then_raises_rate_limited():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, text="slow down")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RateLimited):
            await get_json(client, "https://h.test/x", "h.test")
    assert calls == 2  # original plus one retry


async def test_get_json_returns_on_success():
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await get_json(client, "https://h.test/x", "h.test")
    assert resp.json() == {"ok": True}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_http.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.fetchers.http'`

- [ ] **Step 3: Write the client and limiter**

Create `src/casefile/fetchers/http.py`:

```python
"""The one place an httpx client is built, and the shared outbound rate limiter."""

import asyncio
import random
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx

from casefile import __version__
from casefile.fetchers import RateLimited

USER_AGENT = f"casefile/{__version__} (+https://github.com/cpwillis/casefile)"

_GLOBAL = asyncio.Semaphore(20)
_PER_HOST: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(4))


def build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"user-agent": USER_AGENT},
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=20.0),
        follow_redirects=True,
    )


@asynccontextmanager
async def domain_slot(host: str):
    async with _GLOBAL, _PER_HOST[host]:
        await asyncio.sleep(random.uniform(0, 0.25))  # jitter, politeness not security
        yield


async def get_json(client: httpx.AsyncClient, url: str, host: str, **kwargs) -> httpx.Response:
    """GET with one retry on 429/5xx. Raises RateLimited if still 429 after the retry."""
    async with domain_slot(host):
        resp = await client.get(url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(0.5)  # single backoff
            resp = await client.get(url, **kwargs)
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        resp.raise_for_status()
        return resp
```

Note: `random.uniform` is fine here; this is application code, not a workflow script. The jitter is politeness, not a security boundary.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_http.py -v`
Expected: PASS, 5 cases.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/http.py tests/test_http.py
git commit -m "add shared http client with user-agent, timeouts and rate limiter"
```

---

### Task 5: run_fetcher — orchestration and state mapping

**Files:**
- Modify: `src/casefile/fetchers/__init__.py`
- Modify: `tests/test_fetchers.py`

**Interfaces:**
- Consumes: `registered_fetcher`, `Finding`, `SourceResult`, `State`, `NeedsKey`, `RateLimited`; `httpx`.
- Produces: `async def run_fetcher(source_id: str, value: str, entity_type: EntityType, client: httpx.AsyncClient) -> SourceResult`.

State mapping, exhaustive:

| Fetcher outcome | State |
|---|---|
| returns a non-empty list | `ok` |
| returns an empty list | `empty` |
| raises `NeedsKey` | `needs_key` |
| raises `RateLimited` | `rate_limited` |
| raises `httpx.TimeoutException` | `timeout` |
| raises anything else | `error` (detail = str(exc)) |
| unknown `source_id` | `error` (detail names the missing id) |

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fetchers.py`:

```python
import httpx

from casefile.fetchers import run_fetcher


def _register(id, behaviour):
    @fetcher(id=id, accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return await behaviour(value)

    return f


async def _ok(value):
    return [Finding(label="A", value=value)]


async def _empty(value):
    return []


async def _needs_key(value):
    raise NeedsKey("set X")


async def _rate(value):
    raise RateLimited("429")


async def _timeout(value):
    raise httpx.ReadTimeout("slow")


async def _boom(value):
    raise ValueError("kaboom")


async def test_states_map_from_fetcher_outcomes():
    _register("s-ok", _ok)
    _register("s-empty", _empty)
    _register("s-key", _needs_key)
    _register("s-rate", _rate)
    _register("s-timeout", _timeout)
    _register("s-boom", _boom)
    cases = {
        "s-ok": State.OK,
        "s-empty": State.EMPTY,
        "s-key": State.NEEDS_KEY,
        "s-rate": State.RATE_LIMITED,
        "s-timeout": State.TIMEOUT,
        "s-boom": State.ERROR,
    }
    for sid, expected in cases.items():
        r = await run_fetcher(sid, "example.com", EntityType.DOMAIN, client=None)
        assert r.state == expected, sid
        assert r.source_id == sid


async def test_ok_carries_findings_and_error_carries_detail():
    _register("s-ok2", _ok)
    _register("s-boom2", _boom)
    ok = await run_fetcher("s-ok2", "example.com", EntityType.DOMAIN, client=None)
    assert ok.findings == (Finding(label="A", value="example.com"),)
    err = await run_fetcher("s-boom2", "example.com", EntityType.DOMAIN, client=None)
    assert err.detail == "kaboom"


async def test_unknown_source_is_an_error_not_a_crash():
    r = await run_fetcher("ghost", "example.com", EntityType.DOMAIN, client=None)
    assert r.state == State.ERROR
    assert "ghost" in r.detail
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_fetchers.py -k run_fetcher -v`
Expected: FAIL with `ImportError: cannot import name 'run_fetcher'`

- [ ] **Step 3: Add run_fetcher**

Append to `src/casefile/fetchers/__init__.py` (add `import time` and `import httpx` to the imports):

```python
async def run_fetcher(source_id, value, entity_type, client) -> "SourceResult":
    """Run one fetcher and map its outcome to a SourceResult. Never raises."""
    rec = registered_fetcher(source_id)
    if rec is None:
        return SourceResult(source_id=source_id, state=State.ERROR, detail=f"no fetcher registered for {source_id}")
    start = time.monotonic()
    try:
        findings = tuple(await rec.func(value, entity_type, client))
        state = State.OK if findings else State.EMPTY
        return SourceResult(source_id, state, findings, elapsed_ms=_ms(start))
    except NeedsKey as exc:
        return SourceResult(source_id, State.NEEDS_KEY, detail=str(exc), elapsed_ms=_ms(start))
    except RateLimited as exc:
        return SourceResult(source_id, State.RATE_LIMITED, detail=str(exc), elapsed_ms=_ms(start))
    except httpx.TimeoutException:
        return SourceResult(source_id, State.TIMEOUT, detail="no response within the timeout", elapsed_ms=_ms(start))
    except Exception as exc:  # noqa: BLE001 -- a dead source must never break the page
        return SourceResult(source_id, State.ERROR, detail=str(exc), elapsed_ms=_ms(start))


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_fetchers.py -v`
Expected: PASS. The tests pass `client=None` because the fake fetchers never touch it; real fetchers receive a real client from the caller.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/__init__.py tests/test_fetchers.py
git commit -m "add run_fetcher with exhaustive state mapping"
```

---

### Task 6: The three fetchers

**Files:**
- Create: `src/casefile/fetchers/sources.py`
- Create: `tests/test_sources.py`

**Interfaces:**
- Consumes: `fetcher`, `Finding`, `get_json`; `EntityType`; `httpx`.
- Produces: three registered fetchers with ids `dns`, `rdap`, `crtsh`. Importing this module populates the registry.

Design: each fetcher parses one API's JSON into `Finding`s and returns a list. It raises nothing itself for empty results (returns `[]`, which `run_fetcher` maps to `empty`). Network/HTTP failures propagate from `get_json` and `run_fetcher` classifies them.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sources.py`. These use `httpx.MockTransport`, so no network:

```python
import httpx

from casefile.fetchers import Finding, registered_fetcher, run_fetcher
from casefile.fetchers.sources import crtsh, dns, rdap  # noqa: F401 -- import registers them
from casefile.types import EntityType


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_dns_parses_answer_records():
    def handler(request):
        assert "example.com" in str(request.url)
        return httpx.Response(200, json={"Answer": [{"type": 1, "data": "192.0.2.10"}, {"type": 15, "data": "0 ."}]})

    async with _client(handler) as client:
        findings = await dns("example.com", EntityType.DOMAIN, client)
    assert Finding(label="A", value="192.0.2.10") in findings


async def test_dns_of_an_email_uses_the_domain_part():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"Answer": []})

    async with _client(handler) as client:
        await dns("user@example.com", EntityType.EMAIL, client)
    assert "example.com" in seen["url"]
    assert "user" not in seen["url"].split("name=")[1]


async def test_rdap_pulls_registration_fields():
    def handler(request):
        return httpx.Response(
            200,
            json={"handle": "EXAMPLE", "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}]},
        )

    async with _client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    assert any(f.label == "registration" for f in findings)


async def test_crtsh_dedupes_names():
    def handler(request):
        return httpx.Response(
            200,
            json=[{"name_value": "a.example.com\nexample.com"}, {"name_value": "a.example.com"}],
        )

    async with _client(handler) as client:
        findings = await crtsh("example.com", EntityType.DOMAIN, client)
    values = sorted(f.value for f in findings)
    assert values == ["a.example.com", "example.com"]


async def test_empty_answer_becomes_empty_state():
    def handler(request):
        return httpx.Response(200, json={"Answer": []})

    async with _client(handler) as client:
        r = await run_fetcher("dns", "example.com", EntityType.DOMAIN, client)
    assert r.state == "empty"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.fetchers.sources'`

- [ ] **Step 3: Write the fetchers**

Create `src/casefile/fetchers/sources.py`:

```python
"""Concrete keyless fetchers. Importing this module registers them."""

import httpx

from casefile.fetchers import Finding, fetcher
from casefile.fetchers.http import get_json
from casefile.types import EntityType

_DNS_TYPES = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS"}


@fetcher(id="dns", accepts=[EntityType.DOMAIN, EntityType.EMAIL])
async def dns(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    name = value.split("@")[-1] if entity_type is EntityType.EMAIL else value
    findings: list[Finding] = []
    for qtype in ("A", "AAAA", "MX", "TXT", "NS"):
        url = f"https://cloudflare-dns.com/dns-query?name={name}&type={qtype}"
        resp = await get_json(client, url, "cloudflare-dns.com", headers={"accept": "application/dns-json"})
        for row in resp.json().get("Answer", []):
            label = _DNS_TYPES.get(row.get("type"), str(row.get("type")))
            findings.append(Finding(label=label, value=row.get("data", "")))
    return findings


@fetcher(id="rdap", accepts=[EntityType.DOMAIN, EntityType.IP, EntityType.ASN])
async def rdap(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    kind = {EntityType.DOMAIN: "domain", EntityType.IP: "ip", EntityType.ASN: "autnum"}[entity_type]
    key = value[2:] if entity_type is EntityType.ASN else value  # rdap wants a bare AS number
    resp = await get_json(client, f"https://rdap.org/{kind}/{key}", "rdap.org")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
    for event in data.get("events", []):
        findings.append(Finding(label=event.get("eventAction", "event"), value=event.get("eventDate", "")))
    return findings


@fetcher(id="crtsh", accepts=[EntityType.DOMAIN])
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(client, f"https://crt.sh/?q={value}&output=json", "crt.sh")
    names: set[str] = set()
    for row in resp.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)
    return [Finding(label="subdomain", value=n, url=f"https://{n}") for n in sorted(names)]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_sources.py -v`
Expected: PASS, 5 cases.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/sources.py tests/test_sources.py
git commit -m "add dns, rdap and crtsh fetchers"
```

---

### Task 7: Panel template, rendering and the /panel route

**Files:**
- Create: `src/casefile/web/templates/panel.html`
- Modify: `src/casefile/web/app.py`
- Modify: `src/casefile/web/static/casefile.css`
- Create: `tests/test_panels.py`

**Interfaces:**
- Consumes: `run_fetcher`, `fetchers_for`, `build_client`; `SourceResult`, `State`; `EntityType`.
- Produces: route `GET /panel/{source_id}` reading `?v=` and `?t=`, returning the rendered `panel.html` partial.

Panels are driven by the registry, not the catalogue: a panel shows for every registered
fetcher accepting the type. Some fetchers (dns, rdap) are API sources with no human link
entry, so intersecting with the catalogue would wrongly hide them. The spec's "every
fetcher is also a link" is aspirational; panel-only fetchers are fine.

- [ ] **Step 1: Write the failing test**

Create `tests/test_panels.py`:

```python
from starlette.testclient import TestClient

import casefile.fetchers.sources  # noqa: F401 -- register the real fetchers
from casefile.fetchers import fetchers_for
from casefile.types import EntityType
from casefile.web.app import app

client = TestClient(app)


def test_domain_has_the_three_fetchers_registered():
    ids = fetchers_for(EntityType.DOMAIN)
    assert {"dns", "rdap", "crtsh"} <= set(ids)


def test_panel_route_renders_a_state(monkeypatch):
    from casefile.fetchers import Finding, SourceResult, State

    async def fake_run(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="A", value="192.0.2.10"),))

    monkeypatch.setattr("casefile.web.app.run_fetcher", fake_run)
    resp = client.get("/panel/dns", params={"v": "example.com", "t": "domain"})
    assert resp.status_code == 200
    assert "192.0.2.10" in resp.text
    assert 'data-state="ok"' in resp.text


def test_panel_empty_and_error_render_differently(monkeypatch):
    from casefile.fetchers import SourceResult, State

    async def fake(source_id, value, entity_type, client):
        state = State.EMPTY if source_id == "e" else State.ERROR
        return SourceResult(source_id, state, detail=None if state == State.EMPTY else "boom")

    monkeypatch.setattr("casefile.web.app.run_fetcher", fake)
    empty = client.get("/panel/e", params={"v": "example.com", "t": "domain"}).text
    error = client.get("/panel/x", params={"v": "example.com", "t": "domain"}).text
    assert 'data-state="empty"' in empty
    assert 'data-state="error"' in error
    assert "boom" in error


def test_panel_escapes_untrusted_findings(monkeypatch):
    from casefile.fetchers import Finding, SourceResult, State

    async def fake(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="x", value="<script>alert(1)</script>"),))

    monkeypatch.setattr("casefile.web.app.run_fetcher", fake)
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_panel_with_bad_type_does_not_crash():
    resp = client.get("/panel/dns", params={"v": "example.com", "t": "not-a-type"})
    assert resp.status_code == 200
    assert 'data-state="error"' in resp.text
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_panels.py -v`
Expected: FAIL with `ModuleNotFoundError` on `casefile.web.app` (no `/panel` route yet) or the panel assertions failing.

- [ ] **Step 3: Write panel.html**

Create `src/casefile/web/templates/panel.html`:

```html
<div class="panel" data-state="{{ result.state }}">
  <div class="panel-head">
    <span class="panel-id">{{ result.source_id }}</span>
    <span class="panel-state state-{{ result.state }}">{{ result.state | replace('_', ' ') }}</span>
  </div>
  {% if result.state == "ok" %}
  <ul class="findings">
    {% for f in result.findings %}
    <li><span class="f-label">{{ f.label }}</span>
      {% if f.url %}<a href="{{ f.url }}" rel="noreferrer noopener" target="_blank">{{ f.value }}</a>
      {% else %}<span class="f-value">{{ f.value }}</span>{% endif %}
    </li>
    {% endfor %}
  </ul>
  {% elif result.state == "empty" %}
  <p class="muted">responded, nothing found</p>
  {% elif result.state == "needs_key" %}
  <p class="muted">needs a key: {{ result.detail }}</p>
  {% else %}
  <p class="panel-detail">{{ result.detail or result.state }}</p>
  {% endif %}
</div>
```

- [ ] **Step 4: Add the /panel route to app.py**

In `src/casefile/web/app.py`, add these imports:

```python
import casefile.fetchers.sources  # noqa: F401 -- registers the fetchers at import
from casefile.fetchers import run_fetcher
from casefile.fetchers.http import build_client
from casefile.types import EntityType
```

Add the route handler and register it in the `routes=[...]` list (before the `/static` mount):

```python
async def panel(request: Request) -> HTMLResponse:
    source_id = request.path_params["source_id"]
    value = request.query_params.get("v", "")
    try:
        entity_type = EntityType(request.query_params.get("t", ""))
    except ValueError:
        result = SourceResult(source_id, State.ERROR, detail="unknown entity type")
        return templates.TemplateResponse(request, "panel.html", {"result": result})
    async with build_client() as client:
        result = await run_fetcher(source_id, value, entity_type, client)
    return templates.TemplateResponse(request, "panel.html", {"result": result})
```

Add `Route("/panel/{source_id}", panel)` to the routes list, and import `SourceResult, State` from `casefile.fetchers`.

- [ ] **Step 5: Add panel CSS**

Append to `src/casefile/web/static/casefile.css`:

```css
.panel { border: 1px solid var(--line); border-radius: 4px; padding: 8px 12px; margin-bottom: 8px; }
.panel-head { display: flex; justify-content: space-between; align-items: baseline; }
.panel-id { font-weight: 600; }
.panel-state { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.state-ok { color: #2e7d32; }
.state-empty { color: var(--muted); }
.state-error, .state-timeout, .state-rate_limited { color: #c1121f; }
.state-needs_key { color: #b26a00; }
.findings { list-style: none; padding: 0; margin: 6px 0 0; }
.findings li { display: flex; gap: 8px; }
.f-label { color: var(--muted); min-width: 90px; }
.panel-detail { color: #c1121f; margin: 6px 0 0; font-size: 13px; }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_panels.py -v`
Expected: PASS, 5 cases.

- [ ] **Step 7: Commit**

```bash
git add src/casefile/web/templates/panel.html src/casefile/web/app.py src/casefile/web/static/casefile.css tests/test_panels.py
git commit -m "add panel rendering, state styling and the /panel route"
```

---

### Task 8: Self-loading panels in the result page

**Files:**
- Modify: `src/casefile/web/app.py`
- Modify: `src/casefile/web/templates/result.html`
- Modify: `tests/test_web.py`

**Interfaces:**
- Consumes: `fetchers_for`, `has_fetcher`; `links_for` (added here).
- Produces:
  - `report.links_for(candidate: Candidate) -> tuple[Link, ...]`, the shared link builder; `build_report` is refactored to use it.
  - The result route passes registered fetcher ids per section as `panels`; the template emits a self-loading panel div for each. Link-only sources (no fetcher) stay as links.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_web.py`:

```python
def test_result_page_emits_self_loading_panels():
    text = client.get("/q", params={"v": "example.com"}).text
    assert 'hx-get="/panel/crtsh?v=example.com&amp;t=domain"' in text
    assert 'hx-trigger="load"' in text


def test_sources_without_a_fetcher_have_no_panel():
    text = client.get("/q", params={"v": "example.com"}).text
    # censys-search is a link-only catalogue entry, so it must not get a panel div
    assert 'hx-get="/panel/censys-search' not in text
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_web.py -k panels -v`
Expected: FAIL — the result page emits no panels yet.

- [ ] **Step 3: Add the shared link builder to report.py**

In `src/casefile/report.py`, add `links_for` and refactor `build_report` to use it (this keeps link URLs built in exactly one place):

```python
def links_for(candidate) -> tuple[Link, ...]:
    catalog = load_catalog()
    return tuple(
        Link(s.id, s.name, build_url(s, candidate.value), s.notes) for s in sources_for(catalog, candidate.type)
    )


def build_report(raw: str) -> tuple[Section, ...]:
    return tuple(Section(c.type.value, c.value, links_for(c)) for c in detect(raw))
```

Replace the existing `build_report` body with the two-liner above; `Link`, `Section`, `detect`, `load_catalog`, `sources_for`, `build_url` are already imported in report.py.

- [ ] **Step 4: Pass panels and links into the result context**

In `src/casefile/web/app.py`, replace the section-building in the `result` handler with:

```python
    sections = []
    for candidate in detect(raw):
        sections.append(
            {
                "type": candidate.type.value,
                "value": candidate.value,
                "panels": fetchers_for(candidate.type),
                "links": [link for link in links_for(candidate) if not has_fetcher(link.id)],
            }
        )
```

Change app.py imports: remove `from casefile.report import build_report`, add `from casefile.report import links_for` and `from casefile.fetchers import fetchers_for, has_fetcher`. `crtsh` has both a catalogue entry and a fetcher, so it appears as a panel and is filtered out of links, never both.

- [ ] **Step 5: Emit panel divs in result.html**

In `src/casefile/web/templates/result.html`, inside each `<section class="type-section">`, before the `<h3 id="links-...">` line, add:

```html
      {% if section.panels %}
      <h3>Sources</h3>
      <div class="panels">
        {% for sid in section.panels %}
        <div class="panel" data-state="loading"
             hx-get="/panel/{{ sid }}?v={{ section.value | urlencode }}&t={{ section.type }}"
             hx-trigger="load" hx-swap="outerHTML">
          <div class="panel-head"><span class="panel-id">{{ sid }}</span>
            <span class="panel-state">loading…</span></div>
        </div>
        {% endfor %}
      </div>
      {% endif %}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_web.py -v`
Expected: PASS. Note the `&amp;` in the assertion: Jinja autoescapes the `&` in the `hx-get` attribute, which is correct HTML.

- [ ] **Step 7: Commit**

```bash
git add src/casefile/report.py src/casefile/web/app.py src/casefile/web/templates/result.html tests/test_web.py
git commit -m "add shared link builder, emit self-loading htmx panels per fetcher"
```

---

### Task 9: CLI fan-out

**Files:**
- Modify: `src/casefile/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `detect`, `fetchers_for`, `run_fetcher`, `build_client`; `SourceResult`.
- Produces: `casefile <value>` fetches by default and prints results; `--no-fetch` skips fetching (links only). JSON output gains a `sources` array per candidate.

- [ ] **Step 1: Write the failing test**

The existing offline tests must not hit the network, so they gain `--no-fetch`. Update `tests/test_cli.py`: change `main(["example.com"])` to `main(["example.com", "--no-fetch"])` in `test_text_output_lists_types_and_links`, and `main(["example.com", "--json"])` to `main(["example.com", "--json", "--no-fetch"])` in `test_json_output_is_valid_and_structured`. Then append:

```python
def test_fetch_fans_out_over_registered_sources(monkeypatch, capsys):
    import casefile.cli as climod
    from casefile.fetchers import Finding, SourceResult, State

    async def fake_run(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="A", value="192.0.2.10"),))

    monkeypatch.setattr(climod, "run_fetcher", fake_run)
    assert main(["example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert any(s["state"] == "ok" for s in domain["sources"])


def test_no_fetch_omits_sources(monkeypatch, capsys):
    assert main(["example.com", "--json", "--no-fetch"]) == 0
    payload = json.loads(capsys.readouterr().out)
    domain = next(c for c in payload["candidates"] if c["type"] == "domain")
    assert domain["sources"] == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `--no-fetch` is unknown and `sources` is absent.

- [ ] **Step 3: Add fan-out to cli.py**

In `src/casefile/cli.py`, add imports:

```python
import asyncio
from dataclasses import asdict

import casefile.fetchers.sources  # noqa: F401 -- registers fetchers
from casefile.detect import detect
from casefile.fetchers import fetchers_for, run_fetcher
from casefile.fetchers.http import build_client
from casefile.types import Candidate
```

Add an async fan-out helper and wire it into `main`:

```python
async def _fetch_all(candidates):
    async with build_client() as client:
        results = {}
        for c in candidates:
            ids = fetchers_for(c.type)
            got = await asyncio.gather(*(run_fetcher(sid, c.value, c.type, client) for sid in ids))
            results[(c.type, c.value)] = got
        return results
```

Add `parser.add_argument("--no-fetch", action="store_true", help="skip live fetching, show links only")`.

Replace the positional branch of `main` (everything after the `if args.value is None:` block) with:

```python
    candidates = detect(args.value)
    if not candidates:
        print(f"nothing recognised in {args.value!r}", file=sys.stderr)
        return 1
    results = {} if args.no_fetch else asyncio.run(_fetch_all(candidates))
    render = _render_json if args.json else _render_text
    print(render(args.value, candidates, results))
    return 0
```

Remove the old `Section`-based `_render_text`/`_render_json` and the `from casefile.report import Section, build_report` import; the CLI now builds from `detect` plus the shared `links_for`. Add `from casefile.report import links_for` and define the renderers (`_links` wraps `links_for` into the JSON-friendly dict shape):

```python
def _links(candidate):
    return [{"id": link.id, "name": link.name, "url": link.url} for link in links_for(candidate)]


def _render_text(raw, candidates, results):
    lines = [raw]
    for i, c in enumerate(candidates):
        lines.append("")
        lines.append(f"  {c.type.value.upper():<14} {c.value:<40} {'most likely' if i == 0 else ''}")
        for r in results.get((c.type, c.value), []):
            detail = f" {r.detail}" if r.detail else ""
            lines.append(f"    [{r.state}]{detail} {r.source_id}")
            for f in r.findings:
                lines.append(f"      {f.label}: {f.value}")
        for link in _links(c):
            lines.append(f"    {link['name']:<28} {link['url']}")
    return "\n".join(lines)


def _render_json(raw, candidates, results):
    return json.dumps(
        {
            "input": raw,
            "candidates": [
                {
                    "type": c.type.value,
                    "value": c.value,
                    "sources": [asdict(r) for r in results.get((c.type, c.value), [])],
                    "links": _links(c),
                }
                for c in candidates
            ],
        },
        indent=2,
    )
```

Keep `main`'s argument parsing otherwise unchanged. `report.py` is now used only by any remaining callers; if nothing else imports `build_report`, that is fine, it stays for the demo build in phase 2.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS. Confirm the whole suite still passes: `uv run pytest -q`.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/cli.py tests/test_cli.py
git commit -m "fan out fetchers from the cli with a no-fetch flag"
```

---

### Task 10: Live tests, live workflow, acceptance, release

**Files:**
- Create: `tests/test_live_sources.py`
- Create: `.github/workflows/live.yml`
- Modify: `README.md`
- Modify: `pyproject.toml`, `src/casefile/__init__.py`

**Interfaces:**
- Consumes: everything above.
- Produces: a `0.3.0` candidate with live-verified sources.

- [ ] **Step 1: Write the live tests**

Create `tests/test_live_sources.py`. These are marked `live` and excluded by default:

```python
import pytest

import casefile.fetchers.sources  # noqa: F401
from casefile.fetchers import State, run_fetcher
from casefile.fetchers.http import build_client
from casefile.types import EntityType

pytestmark = pytest.mark.live


async def _run(source_id, value, entity_type):
    async with build_client() as client:
        return await run_fetcher(source_id, value, entity_type, client)


async def test_dns_is_live_and_keyless():
    r = await _run("dns", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}


async def test_rdap_is_live_and_keyless():
    r = await _run("rdap", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}


async def test_crtsh_is_live_and_keyless():
    r = await _run("crtsh", "example.com", EntityType.DOMAIN)
    assert r.state in {State.OK, State.EMPTY}
```

They assert only that a real request succeeds without a key, never specific content.

- [ ] **Step 2: Confirm they are excluded by default and runnable on demand**

Run: `uv run pytest -q` — the live tests must NOT run (no network).
Run: `uv run pytest -m live -v` — these three run against the real services and should pass.
If a live test fails, that source moved; note it, but it does not block the phase.

- [ ] **Step 3: Add the live workflow**

Create `.github/workflows/live.yml`:

```yaml
name: live sources

on:
  workflow_dispatch:
    inputs:
      pattern:
        description: "Optional pytest -k pattern to limit which sources are checked"
        required: false
        default: ""

jobs:
  live:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - run: uv sync --all-extras --dev
      - name: check live sources
        env:
          PATTERN: ${{ inputs.pattern }}
        run: |
          if [ -n "$PATTERN" ]; then
            uv run pytest -m live -k "$PATTERN" -v
          else
            uv run pytest -m live -v
          fi
```

The input goes through `env`, not string interpolation into `run`, to avoid shell injection from a dispatch input.

- [ ] **Step 4: Add the egress note to the README**

Add a short subsection under Usage in `README.md`:

```markdown
### What leaves your machine

casefile fetches live results over **your own connection**, so the sources you query see
your IP. There is no proxy in this version. Fetched data is not stored anywhere yet.
```

- [ ] **Step 5: Bump the version**

Set `version = "0.3.0"` in `pyproject.toml` and `__version__ = "0.3.0"` in `src/casefile/__init__.py`. This also updates the User-Agent automatically.

- [ ] **Step 6: Run the whole suite and lint**

Run: `uv run ruff check && uv run ruff format --check && uv run pytest -q`
Expected: all pass, live tests excluded.

- [ ] **Step 7: Verify the acceptance criteria by hand**

Run: `uv run casefile`, search `example.com`, and confirm: each source shows a panel that loads on its own; a source you kill (temporarily rename `crtsh` in `sources.py` to a bad host and reload) shows a single dead panel while the rest of the page is fine; the six states are reachable. Restore the file after.

Also confirm the User-Agent: `uv run python -c "from casefile.fetchers.http import USER_AGENT; print(USER_AGENT)"` prints `casefile/0.3.0 (+https://github.com/cpwillis/casefile)`.

- [ ] **Step 8: Commit**

```bash
git add tests/test_live_sources.py .github/workflows/live.yml README.md pyproject.toml src/casefile/__init__.py
git commit -m "add live source tests, live workflow, egress note, bump to 0.3.0"
```

Do not tag or push. The repo owner does both.

---

## Acceptance criteria (from the spec)

- Panels self-load via `hx-get`. ✓ Task 8.
- All six panel states render distinctly. ✓ Tasks 5, 7.
- A killed source degrades to one dead panel without affecting the page. ✓ Task 5 (`run_fetcher` never raises), Task 10 step 7.
- The limiter caps concurrency under test. ✓ Task 4.
- Every request carries the project User-Agent. ✓ Task 4, Task 10 step 7.

## Notes for the executor

- **Never `git push`.** Commit locally only.
- **Never `--no-gpg-sign`.** If signing prompts for a passphrase, stop and hand back.
- **No em dashes** in prose you write, including comments and docstrings.
- The registry is module-global. Tests that register fake fetchers use unique ids so they never collide with the real `dns`/`rdap`/`crtsh` or with each other.
- Findings come from third-party APIs and are untrusted. Every path that renders them must go through a Jinja `.html` template (autoescaped). Never build finding HTML by hand.
- Keep `httpx.AsyncClient(` out of every file except `fetchers/http.py`; the constraint test in Task 1 enforces it.
