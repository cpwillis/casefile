# casefile Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `1.0.0`: every entity type with a live source, the WhatsMyName username checker across 716 sites, a SQLite response cache, and a catalogue over the 250-slot bar.

**Architecture:** Six new fetchers register into the existing `@fetcher` registry and need no new plumbing beyond two additions to the shared HTTP module: an `allow` parameter so a 404 can mean `empty` rather than `error`, and a `post_json` sibling for the one source that is POST-only. WhatsMyName is a separate module because it is one fetcher fanning out over 716 vendored site definitions rather than one API call. The cache wraps `run_fetcher` from outside, so the fetch contract stays storage-free.

**Tech Stack:** Python 3.12, httpx (async), `phonenumbers` (offline), stdlib `sqlite3`/`asyncio`/`json`. Existing Starlette + Jinja + HTMX panel machinery is reused unchanged.

**Spec:** [docs/superpowers/specs/2026-08-27-casefile-design.md](../specs/2026-08-27-casefile-design.md)

**Master plan:** [docs/superpowers/plans/2026-08-27-casefile-master-plan.md](2026-08-27-casefile-master-plan.md)

**Depends on:** Phases 1 and 3 (both complete, merged). Independent of Phase 2.

## Verified facts this plan rests on

Every claim below was checked against the live service on 2026-08-28. Re-verify before starting if significant time has passed; free tiers move, which is the whole reason the live suite exists.

| Source | Verified behaviour |
|---|---|
| Shodan InternetDB | Keyless. `GET https://internetdb.shodan.io/{ip}`. A `200` **always** carries the full object (`ip`, `ports`, `hostnames`, `cpes`, `tags`, `vulns`, empty arrays rather than omitted). The **only** no-data signal is `404` with `{"detail":"No information available"}`. Two traps: **private/reserved IPs return `200` with junk** (`10.0.0.1` yields `ports:[161]`), and the rate limit is far below the documented figure, with field reports of a **1-hour IP ban after ~600 requests**. Data refreshes weekly and carries no timestamp. Free for non-commercial use only. |
| GitHub users API | Keyless, 60 req/hour unauthenticated. `404` with `{"message":"Not Found"}` for a nonexistent user. |
| Wikidata | Keyless. `wbsearchentities` returns `{"searchinfo":…, "search":[{"id","label","description","concepturi","url"}]}`. Empty search returns `search: []`. |
| **MalwareBazaar** | **NO LONGER KEYLESS.** `POST https://mb-api.abuse.ch/api/v1/` without an `Auth-Key` header returns `{"error": "Unauthorized"}`. The spec's v1 fetcher list is factually stale on this point. |
| CIRCL hashlookup | Keyless. `GET https://hashlookup.circl.lu/lookup/md5/{hash}` returns file metadata for known hashes, `404` with `{"message":"Non existing MD5"}` for unknown. Note this is known-**good** (NSRL) data, not malware data. |
| WhatsMyName | `wmn-data.json`, **716 sites, 258 KB**, CC BY-SA 4.0, authors listed in the file. Top level: `license`, `authors`, `categories`, `sites`. Per site: `name`, `uri_check`, `e_code`, `e_string`, `m_code`, `m_string`, `known`, `cat`, `protection`. **The placeholder is `{account}`, not `{value}`.** |
| `phonenumbers` 9.x | Offline. `parse(raw, region)` raises `NumberParseException` code `0` ("Missing or invalid default region") when the number has no `+` and no region is passed. `carrier.name_for_number` returns `""` for landlines. `number_type` returns an int enum. |

### Rulings made from those facts

1. **MalwareBazaar becomes a `needs_key` fetcher, not a keyless one.** It reads `ABUSECH_AUTH_KEY` and raises `NeedsKey` when absent. This is the honest handling and it gives the `needs_key` panel state its first real user, which until now was untested against a live source.
2. **CIRCL hashlookup is added so `hash` keeps keyless live coverage.** Its semantics differ from MalwareBazaar (known-legitimate rather than known-malicious), so its findings are labelled to say so. Without it, `hash` would have no live source for a user with no API keys.
3. **The `phonenumbers` fetcher returns an explanatory `Finding` when the number has no country code,** rather than `empty`. `empty` means "looked and found nothing", which is the wrong claim: the truth is "cannot determine region without a `+` prefix", and the user can act on that. No seventh state is invented.

## Global Constraints

- Python `>=3.12`.
- **`phonenumbers` is the fifth and final runtime dependency.** After this phase the complete set is `httpx`, `starlette`, `uvicorn`, `jinja2`, `phonenumbers`. **A sixth dependency is out of scope for this phase**; the `.env` reader and the cache are stdlib.
- Each dependency is added to `pyproject.toml` by the task that first imports it.
- Rate limiting is unchanged and already implemented: global concurrency 20, per-host 4, 0-250 ms jitter, 5 s connect / 20 s read timeouts, exactly one retry on 429/5xx. **Do not re-implement or re-tune it.**
- **InternetDB bans on volume, not per request.** Field reports put a 1-hour IP ban at roughly 600 requests, well under its documented burst figure, and a 429 arrives only once you are already banned. casefile issues one InternetDB request per IP searched, so normal use is nowhere near it; never add a bulk or sweep path over this source.
- **InternetDB is free for non-commercial use only.** Fine for casefile as an MIT tool people run themselves; it would need an enterprise licence inside a paid product. Recorded so it is not discovered later.
- Every outbound request goes through `casefile.fetchers.http`. `httpx.AsyncClient(` is constructed in exactly one file and a constraint test enforces it.
- Six panel states only: `ok`, `empty`, `needs_key`, `rate_limited`, `timeout`, `error`. No new states.
- A dead source renders as a dead panel, never a failed page. `run_fetcher` must keep never raising.
- **Only `ok` and `empty` results are cached.** Caching a `timeout` or `error` for 24 hours turns a transient blip into a day-long lie.
- Findings come from third-party APIs and are untrusted: they render only through autoescaped Jinja `.html` templates, never hand-built HTML.
- Hermetic tests never touch the network; every new fetcher is tested with `httpx.MockTransport`. Live tests are marked `live` and excluded by default.
- WhatsMyName data is vendored **byte-for-byte unmodified** under its CC BY-SA 4.0 licence, with attribution rendered in the UI, not only in the repo.
- Commits are bare lowercase one-line, linear, GPG-signed. No `--no-gpg-sign`. **Never push.**

## Existing interfaces you build on

These already exist and are stable. Do not redefine them.

```python
# casefile.fetchers
@dataclass(frozen=True)
class Finding:  # label: str, value: str, url: str | None = None
@dataclass(frozen=True)
class SourceResult:  # source_id, state, findings=(), detail=None, elapsed_ms=0
class State:  # OK EMPTY NEEDS_KEY RATE_LIMITED TIMEOUT ERROR  (string constants)
class NeedsKey(Exception): ...
class RateLimited(Exception): ...
def fetcher(id: str, accepts: list[EntityType]): ...           # decorator
def fetchers_for(entity_type) -> tuple[str, ...]: ...
def has_fetcher(source_id: str) -> bool: ...
async def run_fetcher(source_id, value, entity_type, client) -> SourceResult: ...  # never raises

# casefile.fetchers.http
USER_AGENT: str
def build_client() -> httpx.AsyncClient: ...
async def domain_slot(host: str): ...                           # async context manager
async def get_json(client, url, host, **kwargs) -> httpx.Response: ...
```

A fetcher is `async def f(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]`.
Existing fetchers pass query strings via `params=`, never f-string interpolation. Follow that.

## File Structure

| File | Responsibility |
|---|---|
| `src/casefile/fetchers/http.py` | Gains `allow` on `get_json` and a `post_json` sibling. |
| `src/casefile/fetchers/sources.py` | Gains the five API fetchers alongside the existing three. |
| `src/casefile/config.py` | Stdlib `.env` reader: `get_key(name)`. No dependency. |
| `src/casefile/fetchers/wmn.py` | WhatsMyName loader and the 716-site checker. Its own module because it is a fan-out, not an API call. |
| `src/casefile/vendor/wmn-data.json` | Vendored dataset, unmodified. |
| `src/casefile/vendor/WMN-LICENCE.txt` | CC BY-SA 4.0 text plus provenance. |
| `src/casefile/cache.py` | SQLite response cache and `run_cached`. |
| `src/casefile/web/app.py` | Panel route calls `run_cached`; adds the WMN attribution to context. |
| `src/casefile/web/templates/panel.html` | Renders per-source attribution when present. |
| `src/casefile/cli.py` | `--no-cache`, `--clear-cache`; fan-out goes through `run_cached`. |
| `src/casefile/catalog/*.toml` | Top-up to cross 250 slots. |
| `tests/test_http.py`, `tests/test_sources.py`, `tests/test_wmn.py`, `tests/test_cache.py`, `tests/test_config.py`, `tests/test_live_sources.py` | One module per source module. |

`sources.py` holds eight small fetchers (~200 lines) rather than eight files: they are the same shape and change for the same reason. `wmn.py` is separate because its logic is genuinely different.

**Vendored data goes inside the package** (`src/casefile/vendor/`), not at the repo root as the spec sketches. Same reasoning as the phase-1 catalogue move: one lookup path, and hatchling ships package data automatically. 258 KB in the wheel is acceptable.

---

### Task 1: HTTP plumbing for 404-as-empty and POST

**Files:**
- Modify: `src/casefile/fetchers/http.py`
- Modify: `tests/test_http.py`

**Interfaces:**
- Consumes: existing `domain_slot`, `RateLimited`.
- Produces:
  - `get_json(client, url, host, *, allow=(), **kwargs) -> httpx.Response` — status codes in `allow` are returned without raising, so a fetcher can inspect `resp.status_code`.
  - `post_json(client, url, host, *, data=None, headers=None, allow=()) -> httpx.Response` — same retry and limiter behaviour, POST with form data.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_http.py`:

```python
async def test_get_json_allow_returns_404_without_raising():
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await get_json(client, "https://h.test/x", "h.test", allow=(404,))
    assert resp.status_code == 404


async def test_get_json_still_raises_on_unallowed_404():
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await get_json(client, "https://h.test/x", "h.test")


async def test_post_json_sends_form_data_and_returns_body():
    seen = {}

    def handler(request):
        seen["body"] = request.content.decode()
        seen["method"] = request.method
        return httpx.Response(200, json={"query_status": "ok"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await post_json(client, "https://h.test/api", "h.test", data={"query": "get_info", "hash": "abc"})
    assert seen["method"] == "POST"
    assert "query=get_info" in seen["body"]
    assert resp.json() == {"query_status": "ok"}


async def test_post_json_retries_once_then_raises_rate_limited():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, text="slow down")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RateLimited):
            await post_json(client, "https://h.test/api", "h.test", data={"a": "b"})
    assert calls == 2
```

Add `post_json` to the existing `from casefile.fetchers.http import ...` line in that file.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_http.py -v`
Expected: FAIL with `ImportError: cannot import name 'post_json'`

- [ ] **Step 3: Implement both**

In `src/casefile/fetchers/http.py`, replace `get_json` with the version below and add `post_json`. The retry logic is identical for both, so it lives in one helper rather than being written twice:

```python
async def _send_with_retry(client, request_factory, host: str, allow: tuple[int, ...]) -> httpx.Response:
    """One request, one retry on 429/5xx, then give up. Statuses in `allow` are returned as-is."""
    async with domain_slot(host):
        resp = await request_factory()
        if resp.status_code == 429 or resp.status_code >= 500:
            await asyncio.sleep(0.5)  # single backoff
            resp = await request_factory()
        if resp.status_code == 429:
            raise RateLimited(f"{host} returned 429")
        if resp.status_code in allow:
            return resp
        resp.raise_for_status()
        return resp


async def get_json(client: httpx.AsyncClient, url: str, host: str, *, allow: tuple[int, ...] = (), **kwargs):
    """GET with one retry. `allow` lists statuses a caller wants to inspect instead of raising."""
    return await _send_with_retry(client, lambda: client.get(url, **kwargs), host, allow)


async def post_json(
    client: httpx.AsyncClient,
    url: str,
    host: str,
    *,
    data: dict | None = None,
    headers: dict | None = None,
    allow: tuple[int, ...] = (),
):
    """POST form data with one retry. Same limiter and retry policy as get_json."""
    return await _send_with_retry(client, lambda: client.post(url, data=data, headers=headers), host, allow)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_http.py -v`
Expected: PASS, including the pre-existing tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/http.py tests/test_http.py
git commit -m "add allow-list statuses and post_json to the shared http layer"
```

---

### Task 2: Stdlib .env reader

**Files:**
- Create: `src/casefile/config.py`
- Create: `tests/test_config.py`
- Modify: `.env.example`

**Interfaces:**
- Consumes: nothing.
- Produces: `get_key(name: str, env_path: Path | None = None) -> str | None` — returns `os.environ[name]` if set, else the value from a `.env` file in the current working directory, else `None`.

The spec promises keys come from a local `.env`. A dependency for that would break the five-dep budget, and the format we need is `KEY=value` lines, which is fifteen lines of stdlib.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
from casefile.config import get_key


def test_environment_wins_over_dotenv(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("MY_KEY=from_file\n")
    monkeypatch.setenv("MY_KEY", "from_env")
    assert get_key("MY_KEY", tmp_path / ".env") == "from_env"


def test_reads_from_dotenv_when_environment_is_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("MY_KEY", raising=False)
    (tmp_path / ".env").write_text("# a comment\n\nMY_KEY = from_file \nOTHER=x\n")
    assert get_key("MY_KEY", tmp_path / ".env") == "from_file"


def test_missing_key_is_none(monkeypatch, tmp_path):
    monkeypatch.delenv("ABSENT", raising=False)
    (tmp_path / ".env").write_text("MY_KEY=v\n")
    assert get_key("ABSENT", tmp_path / ".env") is None


def test_missing_dotenv_file_is_not_an_error(monkeypatch, tmp_path):
    monkeypatch.delenv("ABSENT", raising=False)
    assert get_key("ABSENT", tmp_path / "nope.env") is None


def test_quotes_are_stripped(monkeypatch, tmp_path):
    monkeypatch.delenv("Q", raising=False)
    (tmp_path / ".env").write_text('Q="quoted"\n')
    assert get_key("Q", tmp_path / ".env") == "quoted"


def test_empty_value_is_treated_as_absent(monkeypatch, tmp_path):
    """`.env.example` ships keys with empty values; those must not read as configured."""
    monkeypatch.delenv("BLANK", raising=False)
    (tmp_path / ".env").write_text("BLANK=\n")
    assert get_key("BLANK", tmp_path / ".env") is None
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.config'`

- [ ] **Step 3: Write config.py**

```python
"""Optional API keys, from the environment or a local .env. Stdlib only, by budget."""

import os
from pathlib import Path


def get_key(name: str, env_path: Path | None = None) -> str | None:
    """Environment first, then a .env file. Empty values count as absent."""
    if value := os.environ.get(name, "").strip():
        return value
    path = env_path if env_path is not None else Path.cwd() / ".env"
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if key.strip() == name:
            return raw.strip().strip("\"'").strip() or None
    return None
```

- [ ] **Step 4: Document the key in .env.example**

Ensure `.env.example` contains, with an empty value:

```
# Optional. Without it the MalwareBazaar panel shows "needs a key" and everything else still works.
ABUSECH_AUTH_KEY=
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS, 6 cases.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/config.py tests/test_config.py .env.example
git commit -m "add stdlib dotenv key reader"
```

---

### Task 3: Shodan InternetDB and GitHub fetchers

**Files:**
- Modify: `src/casefile/fetchers/sources.py`
- Modify: `tests/test_sources.py`

**Interfaces:**
- Consumes: `fetcher`, `Finding`, `get_json`, `EntityType`.
- Produces: registered fetchers `internetdb` (accepts `ip`) and `github` (accepts `username`).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources.py`:

```python
async def test_internetdb_lists_ports_and_hostnames():
    def handler(request):
        assert request.url.path == "/192.0.2.10"
        return httpx.Response(
            200,
            json={"ip": "192.0.2.10", "ports": [80, 443], "hostnames": ["a.example.com"], "tags": ["cdn"], "vulns": []},
        )

    async with _client(handler) as client:
        findings = await internetdb("192.0.2.10", EntityType.IP, client)
    labels = {f.label for f in findings}
    assert "port" in labels
    assert Finding(label="hostname", value="a.example.com") in findings


async def test_internetdb_404_is_empty_not_error():
    def handler(request):
        return httpx.Response(404, json={"detail": "No information available"})

    async with _client(handler) as client:
        result = await run_fetcher("internetdb", "192.0.2.10", EntityType.IP, client)
    assert result.state == "empty"


async def test_internetdb_skips_private_addresses_without_a_request():
    """Verified live: 10.0.0.1 returns 200 with junk (ports:[161]), so never ask about internal IPs."""

    def handler(request):
        raise AssertionError("no request should be made for a private address")

    async with _client(handler) as client:
        result = await run_fetcher("internetdb", "10.0.0.1", EntityType.IP, client)
    assert result.state == "empty"


async def test_internetdb_surfaces_cpes_and_vulns():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "ip": "192.0.2.10",
                "ports": [],
                "hostnames": [],
                "cpes": ["cpe:/a:cloudflare:cloudflare"],
                "tags": [],
                "vulns": ["CVE-2021-40438"],
            },
        )

    async with _client(handler) as client:
        findings = await internetdb("192.0.2.10", EntityType.IP, client)
    labels = {f.label for f in findings}
    assert {"cpe", "vuln"} <= labels
    vuln = next(f for f in findings if f.label == "vuln")
    assert vuln.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"


async def test_github_surfaces_profile_fields():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "login": "octocat",
                "name": "The Octocat",
                "company": "GitHub",
                "location": "SF",
                "public_repos": 8,
                "created_at": "2011-01-25T18:44:36Z",
                "html_url": "https://github.com/octocat",
                "blog": "",
            },
        )

    async with _client(handler) as client:
        findings = await github("octocat", EntityType.USERNAME, client)
    values = {f.label: f.value for f in findings}
    assert values["name"] == "The Octocat"
    assert values["company"] == "GitHub"
    assert "blog" not in values  # empty fields are omitted, not shown blank


async def test_github_404_is_empty_not_error():
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    async with _client(handler) as client:
        result = await run_fetcher("github", "nope", EntityType.USERNAME, client)
    assert result.state == "empty"
```

Extend the import line to `from casefile.fetchers.sources import crtsh, dns, github, internetdb, rdap  # noqa: F401`.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL with `ImportError: cannot import name 'internetdb'`

- [ ] **Step 3: Implement both fetchers**

Add `import ipaddress` to the imports at the top of `sources.py`, then append:

```python
@fetcher(id="internetdb", accepts=[EntityType.IP])
async def internetdb(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Keyless Shodan InternetDB. A 200 always carries the full object; 404 is the only miss."""
    address = ipaddress.ip_address(value)
    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
        return []  # verified: 10.0.0.1 returns 200 with junk data, so never ask
    resp = await get_json(
        client,
        f"https://internetdb.shodan.io/{quote(value, safe='')}",
        "internetdb.shodan.io",
        allow=(404,),
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings: list[Finding] = []
    for port in data.get("ports", []):
        findings.append(Finding(label="port", value=str(port)))
    for host in data.get("hostnames", []):
        findings.append(Finding(label="hostname", value=host))
    for cpe in data.get("cpes", []):
        findings.append(Finding(label="cpe", value=cpe))
    for tag in data.get("tags", []):
        findings.append(Finding(label="tag", value=tag))
    for vuln in data.get("vulns", []):
        findings.append(Finding(label="vuln", value=vuln, url=f"https://nvd.nist.gov/vuln/detail/{vuln}"))
    return findings


_GITHUB_FIELDS = ("name", "company", "location", "bio", "blog", "public_repos", "created_at")


@fetcher(id="github", accepts=[EntityType.USERNAME])
async def github(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(
        client,
        f"https://api.github.com/users/{quote(value, safe='')}",
        "api.github.com",
        allow=(404,),
        headers={"accept": "application/vnd.github+json"},
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings = [
        Finding(label=field, value=str(data[field])) for field in _GITHUB_FIELDS if data.get(field) not in (None, "", 0)
    ]
    if url := data.get("html_url"):
        findings.append(Finding(label="profile", value=data.get("login", value), url=url))
    return findings
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sources.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/sources.py tests/test_sources.py
git commit -m "add shodan internetdb and github fetchers"
```

---

### Task 4: Wikidata and CIRCL hashlookup fetchers

**Files:**
- Modify: `src/casefile/fetchers/sources.py`
- Modify: `tests/test_sources.py`

**Interfaces:**
- Consumes: `fetcher`, `Finding`, `get_json`, `EntityType`.
- Produces: registered fetchers `wikidata` (accepts `person`, `company`) and `hashlookup` (accepts `hash`).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources.py`:

```python
async def test_wikidata_returns_entity_matches():
    def handler(request):
        assert request.url.params["action"] == "wbsearchentities"
        return httpx.Response(
            200,
            json={
                "search": [
                    {
                        "id": "Q4778915",
                        "label": "Cloudflare",
                        "description": "American internet infrastructure company",
                        "concepturi": "http://www.wikidata.org/entity/Q4778915",
                    }
                ]
            },
        )

    async with _client(handler) as client:
        findings = await wikidata("Cloudflare", EntityType.COMPANY, client)
    assert findings[0].label == "Cloudflare"
    assert "internet infrastructure" in findings[0].value
    assert findings[0].url == "https://www.wikidata.org/wiki/Q4778915"


async def test_wikidata_no_matches_is_empty():
    def handler(request):
        return httpx.Response(200, json={"search": []})

    async with _client(handler) as client:
        result = await run_fetcher("wikidata", "zzzz", EntityType.COMPANY, client)
    assert result.state == "empty"


async def test_hashlookup_reports_a_known_file():
    def handler(request):
        assert request.url.path.startswith("/lookup/md5/")
        return httpx.Response(
            200,
            json={
                "FileName": "requires.txt",
                "FileSize": "0",
                "MD5": "D41D8CD9",
                "ProductCode": {"ProductName": "Photoshop"},
            },
        )

    async with _client(handler) as client:
        findings = await hashlookup("d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH, client)
    labels = {f.label: f.value for f in findings}
    assert labels["known file"] == "requires.txt"
    assert labels["product"] == "Photoshop"


async def test_hashlookup_unknown_hash_is_empty():
    def handler(request):
        return httpx.Response(404, json={"message": "Non existing MD5"})

    async with _client(handler) as client:
        result = await run_fetcher("hashlookup", "0" * 32, EntityType.HASH, client)
    assert result.state == "empty"


async def test_hashlookup_picks_the_endpoint_by_hash_length():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        return httpx.Response(404, json={"message": "nope"})

    async with _client(handler) as client:
        await hashlookup("a" * 40, EntityType.HASH, client)
    assert "sha1" in seen["path"]
```

Extend the import to include `hashlookup, wikidata`.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL with `ImportError: cannot import name 'wikidata'`

- [ ] **Step 3: Implement both fetchers**

Append to `src/casefile/fetchers/sources.py`:

```python
@fetcher(id="wikidata", accepts=[EntityType.PERSON, EntityType.COMPANY])
async def wikidata(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(
        client,
        "https://www.wikidata.org/w/api.php",
        "www.wikidata.org",
        params={
            "action": "wbsearchentities",
            "search": value,
            "language": "en",
            "format": "json",
            "limit": 5,
        },
    )
    findings: list[Finding] = []
    for item in resp.json().get("search", []):
        entity_id = item.get("id", "")
        findings.append(
            Finding(
                label=item.get("label", entity_id),
                value=item.get("description", "no description"),
                url=f"https://www.wikidata.org/wiki/{entity_id}" if entity_id else None,
            )
        )
    return findings


# hashlookup exposes one path per digest length. Our detector accepts 32/40/64 hex chars.
_HASHLOOKUP_PATHS = {32: "md5", 40: "sha1", 64: "sha256"}


@fetcher(id="hashlookup", accepts=[EntityType.HASH])
async def hashlookup(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """CIRCL hashlookup: known-GOOD (NSRL) data, so a hit means a recognised legitimate file."""
    kind = _HASHLOOKUP_PATHS.get(len(value))
    if kind is None:
        return []
    resp = await get_json(
        client,
        f"https://hashlookup.circl.lu/lookup/{kind}/{quote(value, safe='')}",
        "hashlookup.circl.lu",
        allow=(404,),
        headers={"accept": "application/json"},
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings: list[Finding] = []
    if name := data.get("FileName"):
        findings.append(Finding(label="known file", value=str(name)))
    if size := data.get("FileSize"):
        findings.append(Finding(label="size", value=f"{size} bytes"))
    product = (data.get("ProductCode") or {}).get("ProductName")
    if product:
        findings.append(Finding(label="product", value=str(product)))
    return findings
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sources.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/sources.py tests/test_sources.py
git commit -m "add wikidata and circl hashlookup fetchers"
```

---

### Task 5: MalwareBazaar as a needs-key fetcher

**Files:**
- Modify: `src/casefile/fetchers/sources.py`
- Modify: `tests/test_sources.py`

**Interfaces:**
- Consumes: `fetcher`, `Finding`, `NeedsKey`, `post_json`, `get_key`, `EntityType`.
- Produces: registered fetcher `malwarebazaar` (accepts `hash`).

Verified live: without an `Auth-Key` header this API returns `{"error": "Unauthorized"}`. It is therefore the project's first genuine `needs_key` source, and the state exists precisely for this.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources.py`:

```python
async def test_malwarebazaar_without_a_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: None)

    def handler(request):  # must never be called
        raise AssertionError("no request should be made without a key")

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "needs_key"
    assert "ABUSECH_AUTH_KEY" in result.detail


async def test_malwarebazaar_with_a_key_posts_and_parses(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "secret")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("auth-key")
        seen["body"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "file_name": "evil.exe",
                        "file_type": "exe",
                        "signature": "AgentTesla",
                        "first_seen": "2026-01-01",
                        "tags": ["exe", "trojan"],
                    }
                ],
            },
        )

    async with _client(handler) as client:
        findings = await malwarebazaar("a" * 64, EntityType.HASH, client)
    assert seen["auth"] == "secret"
    assert "query=get_info" in seen["body"]
    labels = {f.label: f.value for f in findings}
    assert labels["signature"] == "AgentTesla"
    assert labels["file"] == "evil.exe"


async def test_malwarebazaar_hash_not_found_is_empty(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "secret")

    def handler(request):
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "empty"


async def test_malwarebazaar_rejected_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "bad")

    def handler(request):
        return httpx.Response(200, json={"error": "Unauthorized"})

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "needs_key"
```

Extend the import to include `malwarebazaar`.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL with `ImportError: cannot import name 'malwarebazaar'`

- [ ] **Step 3: Implement it**

Add the imports `from casefile.config import get_key` and `from casefile.fetchers import Finding, NeedsKey, fetcher` and `from casefile.fetchers.http import get_json, post_json` at the top of `sources.py`, then append:

```python
@fetcher(id="malwarebazaar", accepts=[EntityType.HASH])
async def malwarebazaar(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """abuse.ch requires an Auth-Key as of 2024, so this is a needs_key source by necessity."""
    key = get_key("ABUSECH_AUTH_KEY")
    if not key:
        raise NeedsKey("set ABUSECH_AUTH_KEY in .env to enable MalwareBazaar")
    resp = await post_json(
        client,
        "https://mb-api.abuse.ch/api/v1/",
        "mb-api.abuse.ch",
        data={"query": "get_info", "hash": value},
        headers={"Auth-Key": key},
    )
    payload = resp.json()
    if payload.get("error") == "Unauthorized" or payload.get("query_status") == "unauthorized":
        raise NeedsKey("ABUSECH_AUTH_KEY was rejected by abuse.ch")
    if payload.get("query_status") != "ok":
        return []  # hash_not_found and friends mean looked-and-found-nothing
    findings: list[Finding] = []
    for row in payload.get("data", []):
        if name := row.get("file_name"):
            findings.append(Finding(label="file", value=str(name)))
        if sig := row.get("signature"):
            findings.append(Finding(label="signature", value=str(sig)))
        if ftype := row.get("file_type"):
            findings.append(Finding(label="type", value=str(ftype)))
        if seen := row.get("first_seen"):
            findings.append(Finding(label="first seen", value=str(seen)))
        for tag in row.get("tags") or []:
            findings.append(Finding(label="tag", value=str(tag)))
    return findings
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sources.py -v`
Expected: PASS. Note the first test asserts no HTTP request is attempted without a key: raising before the request is the point.

- [ ] **Step 5: Commit**

```bash
git add src/casefile/fetchers/sources.py tests/test_sources.py
git commit -m "add malwarebazaar as the first needs-key fetcher"
```

---

### Task 6: Offline phone fetcher

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/casefile/fetchers/sources.py`
- Modify: `tests/test_sources.py`

**Interfaces:**
- Consumes: `fetcher`, `Finding`, `EntityType`; `phonenumbers`.
- Produces: registered fetcher `phone_meta` (accepts `phone`). Makes zero network calls.

The id is `phone_meta`, not `phonenumbers`, so it never shadows the library name in the registry or in logs.

- [ ] **Step 1: Add the dependency**

In `pyproject.toml` add `"phonenumbers>=9.0"` to `dependencies`, giving the final five:

```toml
dependencies = [
  "httpx>=0.28",
  "starlette>=0.41",
  "uvicorn>=0.32",
  "jinja2>=3.1",
  "phonenumbers>=9.0",
]
```

Run: `uv sync`

- [ ] **Step 2: Write the failing test**

Append to `tests/test_sources.py`:

```python
async def test_phone_meta_reports_region_and_formats():
    findings = await phone_meta("+61255500000", EntityType.PHONE, client=None)
    labels = {f.label: f.value for f in findings}
    assert labels["region"] == "AU"
    assert labels["location"] == "Australia"
    assert labels["E.164"] == "+61255500000"
    assert labels["international"] == "+61 2 5550 0000"
    assert labels["valid"] == "yes"


async def test_phone_meta_makes_no_network_call():
    def handler(request):
        raise AssertionError("phone_meta must be offline")

    async with _client(handler) as client:
        findings = await phone_meta("+14155550100", EntityType.PHONE, client)
    assert any(f.label == "location" for f in findings)


async def test_phone_meta_without_country_code_explains_itself():
    """Verified: phonenumbers.parse raises 'Missing or invalid default region' with no + prefix.

    That is not "found nothing", it is "cannot tell without a country code", so say so.
    """
    findings = await phone_meta("0255500000", EntityType.PHONE, client=None)
    assert len(findings) == 1
    assert findings[0].label == "note"
    assert "country code" in findings[0].value


async def test_phone_meta_unparseable_is_empty():
    findings = await phone_meta("+999", EntityType.PHONE, client=None)
    assert findings == []
```

Extend the import to include `phone_meta`.

- [ ] **Step 3: Run it to verify it fails**

Run: `uv run pytest tests/test_sources.py -v`
Expected: FAIL with `ImportError: cannot import name 'phone_meta'`

- [ ] **Step 4: Implement it**

Add `import phonenumbers` and `from phonenumbers import PhoneNumberFormat, carrier, geocoder, timezone` to `sources.py`, then append:

```python
_PHONE_TYPES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
    phonenumbers.PhoneNumberType.VOIP: "voip",
}


@fetcher(id="phone_meta", accepts=[EntityType.PHONE])
async def phone_meta(value: str, entity_type: EntityType, client) -> list[Finding]:
    """Offline. libphonenumber metadata only; makes no network request at all."""
    try:
        parsed = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException as exc:
        if exc.error_type == phonenumbers.NumberParseException.INVALID_COUNTRY_CODE:
            return [
                Finding(
                    label="note",
                    value="no country code: prefix with + and the country code for region, carrier and timezone",
                )
            ]
        return []
    findings = [Finding(label="valid", value="yes" if phonenumbers.is_valid_number(parsed) else "no")]
    if region := phonenumbers.region_code_for_number(parsed):
        findings.append(Finding(label="region", value=region))
    if location := geocoder.description_for_number(parsed, "en"):
        findings.append(Finding(label="location", value=location))
    if name := carrier.name_for_number(parsed, "en"):  # empty for most landlines
        findings.append(Finding(label="carrier", value=name))
    for zone in timezone.time_zones_for_number(parsed):
        findings.append(Finding(label="timezone", value=zone))
    if label := _PHONE_TYPES.get(phonenumbers.number_type(parsed)):
        findings.append(Finding(label="line type", value=label))
    findings.append(Finding(label="E.164", value=phonenumbers.format_number(parsed, PhoneNumberFormat.E164)))
    findings.append(
        Finding(label="international", value=phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL))
    )
    return findings
```

`INVALID_COUNTRY_CODE` is the error type libphonenumber raises for "Missing or invalid default region", verified against version 9.0.38.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sources.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/casefile/fetchers/sources.py tests/test_sources.py
git commit -m "add offline phone metadata fetcher, the fifth and final dependency"
```

---

### Task 7: Vendor the WhatsMyName dataset

**Files:**
- Create: `src/casefile/vendor/__init__.py`
- Create: `src/casefile/vendor/wmn-data.json`
- Create: `src/casefile/vendor/WMN-LICENCE.txt`
- Create: `tests/test_wmn.py`
- Modify: `src/casefile/fetchers/wmn.py` (created here)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `WMN_ATTRIBUTION: str` — the credit line rendered in the UI.
  - `load_sites() -> tuple[Site, ...]`, cached, where `Site` is a frozen dataclass with `name: str`, `uri_check: str`, `e_code: int`, `e_string: str`, `m_code: int`, `m_string: str`, `cat: str`, `protection: tuple[str, ...]`.
  - `check_url(site: Site, username: str) -> str` — substitutes the `{account}` placeholder, URL-encoded.

- [ ] **Step 1: Vendor the data and licence**

```bash
mkdir -p src/casefile/vendor
echo '# Third-party vendored data. Unmodified; see WMN-LICENCE.txt.' > src/casefile/vendor/__init__.py
curl -L https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json \
  -o src/casefile/vendor/wmn-data.json
python3 -c "
import json; d=json.load(open('src/casefile/vendor/wmn-data.json'))
print('sites:', len(d['sites'])); assert len(d['sites']) > 600
"
```

Expected: prints a site count over 600 (716 at time of writing). If the file is an HTML error page, stop and fix.

Create `src/casefile/vendor/WMN-LICENCE.txt`:

```
WhatsMyName (wmn-data.json)
Source: https://github.com/WebBreacher/WhatsMyName
Copyright (C) 2015-2026 Micah Hoffman and contributors.

Licensed under the Creative Commons Attribution-ShareAlike 4.0 International
License: http://creativecommons.org/licenses/by-sa/4.0/

This file is vendored BYTE-FOR-BYTE UNMODIFIED. Share-alike attaches to
modifications of the dataset, so casefile never edits it; any casefile-specific
overrides live in first-party files that reference site names instead.
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_wmn.py`:

```python
from casefile.fetchers.wmn import WMN_ATTRIBUTION, check_url, load_sites


def test_dataset_loads_with_many_sites():
    sites = load_sites()
    assert len(sites) > 600


def test_every_site_has_a_usable_check_url():
    for site in load_sites():
        assert "{account}" in site.uri_check, site.name


def test_check_url_substitutes_and_encodes():
    (site,) = [s for s in load_sites() if "{account}" in s.uri_check][:1]
    url = check_url(site, "a b/c")
    assert "{account}" not in url
    assert "a%20b%2Fc" in url


def test_attribution_names_the_project_and_licence():
    assert "WhatsMyName" in WMN_ATTRIBUTION
    assert "CC BY-SA 4.0" in WMN_ATTRIBUTION


def test_protection_flags_are_exposed():
    sites = load_sites()
    assert any(s.protection for s in sites), "the dataset marks captcha/cloudflare sites"
```

- [ ] **Step 3: Run it to verify it fails**

Run: `uv run pytest tests/test_wmn.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.fetchers.wmn'`

- [ ] **Step 4: Write the loader**

Create `src/casefile/fetchers/wmn.py`:

```python
"""WhatsMyName: 716 vendored site definitions and the username checker over them.

Data is CC BY-SA 4.0 and vendored unmodified. See src/casefile/vendor/WMN-LICENCE.txt.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

DATA_PATH = Path(__file__).resolve().parents[1] / "vendor" / "wmn-data.json"
WMN_ATTRIBUTION = (
    "Username checks use the WhatsMyName dataset by Micah Hoffman and contributors, "
    "licensed CC BY-SA 4.0: https://github.com/WebBreacher/WhatsMyName"
)
PLACEHOLDER = "{account}"


@dataclass(frozen=True, slots=True)
class Site:
    name: str
    uri_check: str
    e_code: int
    e_string: str
    m_code: int
    m_string: str
    cat: str
    protection: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def load_sites() -> tuple[Site, ...]:
    document = json.loads(DATA_PATH.read_text())
    return tuple(
        Site(
            name=raw["name"],
            uri_check=raw["uri_check"],
            e_code=int(raw.get("e_code", 200)),
            e_string=raw.get("e_string", "") or "",
            m_code=int(raw.get("m_code", 404)),
            m_string=raw.get("m_string", "") or "",
            cat=raw.get("cat", "other"),
            protection=tuple(raw.get("protection", ()) or ()),
        )
        for raw in document.get("sites", [])
        if PLACEHOLDER in raw.get("uri_check", "")
    )


def check_url(site: Site, username: str) -> str:
    return site.uri_check.replace(PLACEHOLDER, quote(username, safe=""))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_wmn.py -v`
Expected: PASS, 5 cases.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/vendor src/casefile/fetchers/wmn.py tests/test_wmn.py
git commit -m "vendor the whatsmyname dataset with its licence and loader"
```

---

### Task 8: The WhatsMyName checker

**Files:**
- Modify: `src/casefile/fetchers/wmn.py`
- Modify: `src/casefile/fetchers/sources.py`
- Modify: `tests/test_wmn.py`
- Modify: `src/casefile/web/templates/panel.html`

**Interfaces:**
- Consumes: `load_sites`, `check_url`, `Site`, `domain_slot`, `fetcher`, `Finding`.
- Produces:
  - `account_exists(site: Site, status: int, body: str) -> bool` — the false-positive mitigation, pure and directly testable.
  - registered fetcher `whatsmyname` (accepts `username`).

Detection rule, from the dataset's own semantics: an account exists when the response status equals `e_code` **and** (`e_string` is empty **or** `e_string` appears in the body). The `m_code`/`m_string` pair describes the missing case and is used only as a tie-break when `e_string` is empty, because status alone is a weak signal. False positives, not coverage, are the real problem in username enumeration, which is why this is its own tested function.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_wmn.py`:

```python
import httpx
import pytest

from casefile.fetchers import run_fetcher
from casefile.fetchers.wmn import Site, account_exists
from casefile.types import EntityType


def _site(**kw):
    base = dict(
        name="T",
        uri_check="https://t.test/{account}",
        e_code=200,
        e_string="found-me",
        m_code=404,
        m_string="no-user",
        cat="test",
    )
    base.update(kw)
    return Site(**base)


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, "prefix found-me suffix", True),  # code and string both match
        (200, "nothing here", False),  # right code, wrong body: the classic false positive
        (404, "found-me", False),  # wrong code
        (500, "found-me", False),  # server error is not existence
    ],
)
def test_account_exists_requires_code_and_string(status, body, expected):
    assert account_exists(_site(), status, body) is expected


def test_empty_e_string_falls_back_to_code_and_missing_string():
    site = _site(e_string="", m_string="no-user")
    assert account_exists(site, 200, "whatever") is True
    assert account_exists(site, 200, "no-user here") is False  # missing marker present, so absent
    assert account_exists(site, 404, "whatever") is False


async def test_whatsmyname_reports_only_hits(monkeypatch):
    sites = (
        _site(name="Hit", uri_check="https://hit.test/{account}"),
        _site(name="Miss", uri_check="https://miss.test/{account}"),
    )
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: sites)

    def handler(request):
        if request.url.host == "hit.test":
            return httpx.Response(200, text="found-me")
        return httpx.Response(404, text="no-user")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "someone", EntityType.USERNAME, client)
    assert result.state == "ok"
    assert [f.label for f in result.findings] == ["Hit"]
    assert result.findings[0].url == "https://hit.test/someone"


async def test_whatsmyname_no_hits_is_empty(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: (_site(),))

    def handler(request):
        return httpx.Response(404, text="no-user")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "nobody", EntityType.USERNAME, client)
    assert result.state == "empty"


async def test_whatsmyname_survives_a_dead_site(monkeypatch):
    sites = (
        _site(name="Dead", uri_check="https://dead.test/{account}"),
        _site(name="Alive", uri_check="https://alive.test/{account}"),
    )
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: sites)

    def handler(request):
        if request.url.host == "dead.test":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, text="found-me")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "someone", EntityType.USERNAME, client)
    assert [f.label for f in result.findings] == ["Alive"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_wmn.py -v`
Expected: FAIL with `ImportError: cannot import name 'account_exists'`

- [ ] **Step 3: Implement the checker**

First extend the imports **at the top** of `src/casefile/fetchers/wmn.py` so the existing block reads:

```python
import asyncio
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

import httpx

from casefile.fetchers import Finding, fetcher
from casefile.fetchers.http import domain_slot
from casefile.types import EntityType
```

Imports must go at the top, not in the appended block: `ruff` rule E402 fails a module-level
import placed after code, and CI runs `ruff check`.

Then append the checker to the end of the file:

```python
# ponytail: one panel for all 716 sites, so it returns in 30-60s rather than streaming.
# Chunk into ~10 panels of 70 sites if that latency actually annoys anyone.


def account_exists(site: Site, status: int, body: str) -> bool:
    """The false-positive mitigation. Status alone is never enough when a marker exists."""
    if status != site.e_code:
        return False
    if site.e_string:
        return site.e_string in body
    if site.m_string and site.m_string in body:
        return False  # the missing-marker is present, so the account is absent
    return True


async def _check_one(site: Site, username: str, client: httpx.AsyncClient) -> Finding | None:
    url = check_url(site, username)
    host = httpx.URL(url).host
    try:
        async with domain_slot(host):
            resp = await client.get(url)
    except Exception:  # noqa: BLE001 -- one dead site must not sink the other 715
        return None
    if not account_exists(site, resp.status_code, resp.text):
        return None
    note = f"({', '.join(site.protection)})" if site.protection else None
    return Finding(label=site.name, value=note or site.cat, url=url)


@fetcher(id="whatsmyname", accepts=[EntityType.USERNAME])
async def whatsmyname(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    sites = load_sites()
    results = await asyncio.gather(*(_check_one(s, value, client) for s in sites))
    return sorted((f for f in results if f is not None), key=lambda f: f.label.lower())
```

The global concurrency semaphore in `domain_slot` bounds all 716 checks to 20 in flight, so this needs no limiter of its own. Sites flagged with `protection` (captcha, cloudflare) still run, but their finding carries the flag so a hit can be read with appropriate suspicion.

Then register it by importing the module for its side effect. Add to the bottom of `src/casefile/fetchers/sources.py`:

```python
from casefile.fetchers import wmn  # noqa: E402,F401 -- registers the whatsmyname fetcher
```

- [ ] **Step 4: Render the attribution in the panel**

CC BY-SA requires attribution where the material is used, which includes the running UI. In `src/casefile/web/templates/panel.html`, add just before the closing `</div>`:

```html
  {% if result.source_id == "whatsmyname" and result.state in ("ok", "empty") %}
  <p class="attribution muted">Username checks use the <a href="https://github.com/WebBreacher/WhatsMyName"
     rel="noreferrer noopener" target="_blank">WhatsMyName</a> dataset by Micah Hoffman and contributors,
     licensed CC BY-SA 4.0.</p>
  {% endif %}
```

And append to `src/casefile/web/static/casefile.css`:

```css
.attribution { font-size: 11px; margin: 8px 0 0; }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_wmn.py tests/test_panels.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/fetchers/wmn.py src/casefile/fetchers/sources.py src/casefile/web/templates/panel.html src/casefile/web/static/casefile.css tests/test_wmn.py
git commit -m "add the whatsmyname checker with attribution in the ui"
```

---

### Task 9: SQLite response cache

**Files:**
- Create: `src/casefile/cache.py`
- Create: `tests/test_cache.py`
- Modify: `src/casefile/web/app.py`
- Modify: `src/casefile/cli.py`

**Interfaces:**
- Consumes: `run_fetcher`, `SourceResult`, `Finding`, `State`.
- Produces:
  - `cache_path() -> Path` — `${XDG_CACHE_HOME:-~/.cache}/casefile/cache.db`.
  - `async def run_cached(source_id, value, entity_type, client, *, ttl=86400, use_cache=True) -> SourceResult`.
  - `clear_cache() -> int` — deletes all rows, returns how many.

**Only `ok` and `empty` are cached.** A cached `timeout` would turn one bad moment into a day of lying to the user.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cache.py`:

```python
import httpx
import pytest

from casefile.cache import cache_path, clear_cache, run_cached
from casefile.fetchers import Finding, State, fetcher
from casefile.types import EntityType


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    clear_cache()
    yield


def test_cache_path_follows_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_path() == tmp_path / "casefile" / "cache.db"


async def test_second_call_inside_ttl_does_not_re_run_the_fetcher():
    calls = 0

    @fetcher(id="cache-hit", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    first = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    second = await run_cached("cache-hit", "example.com", EntityType.DOMAIN, None)
    assert calls == 1
    assert first.findings == second.findings
    assert second.state == State.OK


async def test_no_cache_bypasses_the_cache():
    calls = 0

    @fetcher(id="cache-bypass", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-bypass", "example.com", EntityType.DOMAIN, None, use_cache=False)
    assert calls == 2


async def test_expired_entries_are_re_fetched():
    calls = 0

    @fetcher(id="cache-ttl", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value="1")]

    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None, ttl=0)
    await run_cached("cache-ttl", "example.com", EntityType.DOMAIN, None, ttl=0)
    assert calls == 2


async def test_errors_are_never_cached():
    calls = 0

    @fetcher(id="cache-error", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        raise ValueError("boom")

    first = await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-error", "example.com", EntityType.DOMAIN, None)
    assert first.state == State.ERROR
    assert calls == 2, "a transient failure must not be cached for the whole TTL"


async def test_empty_is_cached_because_it_is_a_real_answer():
    calls = 0

    @fetcher(id="cache-empty", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return []

    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    await run_cached("cache-empty", "example.com", EntityType.DOMAIN, None)
    assert calls == 1


async def test_clear_cache_empties_it():
    @fetcher(id="cache-clear", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        return [Finding(label="A", value="1")]

    await run_cached("cache-clear", "example.com", EntityType.DOMAIN, None)
    assert clear_cache() >= 1
    assert clear_cache() == 0


async def test_different_values_are_separate_entries():
    calls = 0

    @fetcher(id="cache-keys", accepts=[EntityType.DOMAIN])
    async def f(value, entity_type, client):
        nonlocal calls
        calls += 1
        return [Finding(label="A", value=value)]

    await run_cached("cache-keys", "a.example", EntityType.DOMAIN, None)
    await run_cached("cache-keys", "b.example", EntityType.DOMAIN, None)
    assert calls == 2
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_cache.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'casefile.cache'`

- [ ] **Step 3: Write cache.py**

```python
"""SQLite response cache. Wraps run_fetcher from outside so the fetch contract stays storage-free.

The cache holds third-party data pulled from public sources, so clear_cache is a privacy
control as much as a debugging one.
"""

import json
import os
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from casefile.fetchers import Finding, SourceResult, State, run_fetcher

CACHEABLE = (State.OK, State.EMPTY)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    source_id  TEXT NOT NULL,
    value      TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (source_id, value)
)
"""


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "casefile" / "cache.db"


def _connect() -> sqlite3.Connection:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    return conn


def _load(source_id: str, value: str, ttl: float) -> SourceResult | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE source_id = ? AND value = ?",
            (source_id, value),
        ).fetchone()
    if row is None or time.time() - row[0] > ttl:
        return None
    data = json.loads(row[1])
    findings = tuple(Finding(**f) for f in data.get("findings", []))
    return SourceResult(
        source_id=data["source_id"],
        state=data["state"],
        findings=findings,
        detail=data.get("detail"),
        elapsed_ms=data.get("elapsed_ms", 0),
    )


def _store(result: SourceResult, value: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO responses (source_id, value, fetched_at, payload) VALUES (?, ?, ?, ?)",
            (result.source_id, value, time.time(), json.dumps(asdict(result))),
        )


def clear_cache() -> int:
    """Delete every cached response. Returns the number of rows removed."""
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM responses")
        return cursor.rowcount if cursor.rowcount > 0 else 0


async def run_cached(source_id, value, entity_type, client, *, ttl: float = 86400, use_cache: bool = True):
    """run_fetcher with a SQLite read-through cache. Only ok and empty are stored."""
    if use_cache and (hit := _load(source_id, value, ttl)) is not None:
        return hit
    result = await run_fetcher(source_id, value, entity_type, client)
    if use_cache and result.state in CACHEABLE:
        _store(result, value)
    return result
```

- [ ] **Step 4: Route the web panel and the CLI through the cache**

In `src/casefile/web/app.py`, replace the `from casefile.fetchers import run_fetcher` import with `from casefile.cache import run_cached` and change the call in the `panel` handler from `run_fetcher(source_id, value, entity_type, client)` to `run_cached(source_id, value, entity_type, client)`. Leave the `registered_fetcher` guard above it untouched.

In `src/casefile/cli.py`, add `--no-cache` and `--clear-cache`:

```python
    parser.add_argument("--no-cache", action="store_true", help="bypass the response cache")
    parser.add_argument("--clear-cache", action="store_true", help="purge the response cache and exit")
```

Handle `--clear-cache` first in `main`, before the positional check, since it takes no target:

```python
    if args.clear_cache:
        from casefile.cache import clear_cache

        print(f"cleared {clear_cache()} cached responses")
        return 0
```

And change `_fetch_all` to take the flag and use `run_cached`:

```python
async def _fetch_all(candidates, use_cache: bool = True):
    async with build_client() as client:
        results = {}
        for c in candidates:
            ids = fetchers_for(c.type)
            got = await asyncio.gather(*(run_cached(sid, c.value, c.type, client, use_cache=use_cache) for sid in ids))
            results[(c.type, c.value)] = got
        return results
```

Update its call site to `asyncio.run(_fetch_all(candidates, use_cache=not args.no_cache))` and swap the `run_fetcher` import for `from casefile.cache import run_cached`.

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q`
Expected: all PASS. The web and CLI tests that monkeypatch `run_fetcher` may now need to patch `casefile.web.app.run_cached` or `casefile.cli.run_cached` instead; update those patch targets rather than reverting the wiring.

- [ ] **Step 6: Commit**

```bash
git add src/casefile/cache.py src/casefile/web/app.py src/casefile/cli.py tests/test_cache.py tests/test_panels.py tests/test_cli.py
git commit -m "add sqlite response cache with no-cache and clear-cache"
```

---

### Task 10: Catalogue top-up, live tests, docs, release

**Files:**
- Modify: `src/casefile/catalog/*.toml`
- Modify: `tests/test_catalog_coverage.py`
- Modify: `tests/test_live_sources.py`
- Modify: `README.md`
- Modify: `pyproject.toml`, `src/casefile/__init__.py`

**Interfaces:**
- Consumes: everything above.
- Produces: a `1.0.0` candidate.

The master plan gates `1.0.0` on 250+ catalogue type-slots. The catalogue currently holds **226**, so this is a real gap, not a formality.

- [ ] **Step 1: Raise the coverage bar and watch it fail**

In `tests/test_catalog_coverage.py`, change `MINIMUM_SLOTS = 100` to:

```python
MINIMUM_SLOTS = 250  # the 1.0.0 bar from the master plan
```

Run: `uv run pytest tests/test_catalog_coverage.py -v`
Expected: FAIL, reporting 226 slots against the 250 needed.

- [ ] **Step 2: Add catalogue entries until it passes**

Add at least 24 new type-slots across the existing category files. The new fetcher sources deserve link entries too, since a link works even when a key is missing. Follow the existing entry shape exactly, and every `url` must be `https://` and contain `{value}`:

```toml
[[source]]
id = "hashlookup-circl"
name = "CIRCL hashlookup"
accepts = ["hash"]
url = "https://hashlookup.circl.lu/lookup/md5/{value}"
notes = "known-good NSRL data, keyless"
provenance = "verified 2026-08-28"
```

Author them the same way as phase 1: open the site, run a real search, copy the URL, replace the identifier with `{value}`, and paste it back with a different value to confirm the template works. Roughly an hour for 24 slots.

Run: `uv run pytest tests/test_catalog.py tests/test_catalog_coverage.py -v`
Expected: PASS. `test_catalog.py` enforces https-only, unique ids and the `{value}` placeholder, so a bad entry fails there.

- [ ] **Step 3: Add live tests for the new sources**

Append to `tests/test_live_sources.py`:

```python
async def test_internetdb_is_live_and_keyless():
    r = await _run("internetdb", "8.8.8.8", EntityType.IP)
    assert r.state in {State.OK, State.EMPTY}


async def test_github_is_live_and_keyless():
    r = await _run("github", "octocat", EntityType.USERNAME)
    assert r.state in {State.OK, State.EMPTY}


async def test_wikidata_is_live_and_keyless():
    r = await _run("wikidata", "Cloudflare", EntityType.COMPANY)
    assert r.state in {State.OK, State.EMPTY}


async def test_hashlookup_is_live_and_keyless():
    r = await _run("hashlookup", "d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH)
    assert r.state in {State.OK, State.EMPTY}


async def test_phone_meta_needs_no_network():
    r = await _run("phone_meta", "+14155550100", EntityType.PHONE)
    assert r.state is State.OK


async def test_malwarebazaar_reports_needs_key_without_one():
    """Without ABUSECH_AUTH_KEY this must be needs_key, never error: the state exists for this."""
    r = await _run("malwarebazaar", "a" * 64, EntityType.HASH)
    assert r.state in {State.NEEDS_KEY, State.OK, State.EMPTY}
```

WhatsMyName is deliberately absent from the live suite: 716 real requests is not something to fire from CI, even manually.

Run: `uv run pytest -m live -v`
Expected: the keyless ones pass. A failure means that source moved, which is exactly what this suite is for; note it and continue.

- [ ] **Step 4: Update the README**

Replace the Status section with:

```markdown
## Status

v1.0.0. Detection across 21 entity types, a 250+ slot link catalogue, and live fetching
from six keyless sources plus the 716-site WhatsMyName username checker.

Responses are cached for 24 hours under `${XDG_CACHE_HOME:-~/.cache}/casefile/`.
`casefile --clear-cache` purges it, which is a privacy control as much as a debugging one.

One source needs a key: MalwareBazaar requires a free `ABUSECH_AUTH_KEY` (see `.env.example`).
Without it that panel reads "needs a key" and everything else works normally.
```

And add to the "What leaves your machine" subsection:

```markdown
A username search queries 716 sites, so it takes 30-60 seconds and is the single most
visible thing casefile does from your IP address.
```

- [ ] **Step 5: Bump the version**

Set `version = "1.0.0"` in `pyproject.toml`, `__version__ = "1.0.0"` in `src/casefile/__init__.py`, and change the classifier to `"Development Status :: 5 - Production/Stable"`.

This also updates the User-Agent automatically, since it interpolates `__version__`.

- [ ] **Step 6: Full verification**

Run: `uv run ruff check && uv run ruff format --check && uv run pytest -q`
Expected: all pass, live tests excluded.

Then confirm the wheel still ships the vendored data, which is the failure mode that would silently break `uvx casefile`:

```bash
uv build --wheel 2>&1 | tail -1
python3 -c "
import zipfile, glob
w = sorted(glob.glob('dist/casefile-1.0.0-py3-none-any.whl'))[-1]
names = zipfile.ZipFile(w).namelist()
assert any(n.endswith('wmn-data.json') for n in names), 'WMN DATA MISSING FROM WHEEL'
assert any(n.endswith('WMN-LICENCE.txt') for n in names), 'WMN LICENCE MISSING FROM WHEEL'
print('vendored data ships:', sum(1 for n in names if 'vendor/' in n), 'files')
print('catalogue files:', sum(1 for n in names if n.endswith('.toml')))
"
```

- [ ] **Step 7: Verify the app by hand**

Run: `uv run casefile`, then check each of these in the browser:

- `example.com` shows dns, rdap and crtsh panels loading independently.
- `8.8.8.8` shows an internetdb panel and an rdap panel.
- `octocat` shows a github panel and a whatsmyname panel; the WMN panel takes 30-60 s and renders the CC BY-SA attribution line.
- `+14155550100` shows a phone_meta panel with region, location and both formats, instantly and with no network.
- `d41d8cd98f00b204e9800998ecf8427e` shows a hashlookup panel and a malwarebazaar panel reading "needs a key".
- Re-run the same search: panels return instantly from the cache. Then `casefile --clear-cache` and confirm they are slow again.

- [ ] **Step 8: Commit**

```bash
git add src/casefile/catalog tests/test_catalog_coverage.py tests/test_live_sources.py README.md pyproject.toml src/casefile/__init__.py
git commit -m "top up catalogue past 250 slots, add live tests, bump to 1.0.0"
```

Do not tag or push. The repo owner does both.

---

## Acceptance criteria

- All eight API fetchers plus the WhatsMyName checker return typed `SourceResult`s. Tasks 3-8.
- Every entity type with a live source has one; `hash` has a keyless source and a keyed one. Tasks 4, 5.
- A repeat query inside the TTL issues no network calls. Task 9.
- `--clear-cache` empties the database. Task 9.
- Errors and timeouts are never cached. Task 9.
- WhatsMyName attribution renders in the UI, not only in the repo. Task 8.
- Catalogue at 250+ type-slots. Task 10.
- The wheel ships the vendored dataset and its licence. Task 10 step 6.

## Notes for the executor

- **Never `git push`.** Commit locally only.
- **Never `--no-gpg-sign`.** If signing prompts for a passphrase, stop and hand back.
- **No em dashes** in prose you write, including comments and docstrings.
- Tasks 3 through 6 are the same shape (register a fetcher, parse a response, test with `MockTransport`). Batching them into one dispatch is reasonable; each still needs its own tests.
- `build_report`/`Section` in `report.py` has no production caller and is covered by `tests/test_report.py`. It is phase 2's demo builder. Leave it alone; do not delete it and do not wire it in here.
- The registry is module-global and tests register fakes into it. Use unique ids (`cache-hit`, `cache-ttl`) so they never collide with the real fetchers or each other.
- If a live source has changed shape since 2026-08-28, fix the fetcher to match reality and note it in the commit message. The verified-facts table is a snapshot, not a promise.
