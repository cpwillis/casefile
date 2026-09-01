# casefile

Paste an identifier (domain, IP, ASN, URL, email, username, person, company, phone, hash, CVE, crypto address or tx,
coordinates, MAC, VIN, MMSI, IMO, ICAO24, tail number) and casefile works out what it could be, fetches what keyless
sources will give up, and lists the rest as links you open yourself.

Local only: binds `127.0.0.1`, no account, no telemetry, nothing hosted.

## Run

Not on PyPI yet. The name is reserved there, but the only published version is a `0.0.0` placeholder, so `uvx casefile`
gets a stub until `release.yml` is dispatched. Run from source:

```bash
git clone https://github.com/cpwillis/casefile
cd casefile
uv sync
uv run casefile
```

That starts the local web app and opens a browser on it:

```
casefile is running at http://127.0.0.1:8765
press ctrl-c to stop
```

`--port` if 8765 is taken, `--no-browser` on a headless box. There is no flag to bind another address, on purpose.
Forward the port instead:

```bash
ssh -L 8765:127.0.0.1:8765 user@host
```

## CLI

A positional identifier prints to the terminal instead of starting the server.

```bash
uv run casefile example.com                    # text
uv run casefile example.com --json             # machine-readable
uv run casefile example.com --no-fetch         # links only, no requests
uv run casefile example.com --no-cache         # bypass the response cache for this run
uv run casefile example.com --check-links      # probe each link, flag the ones definitely gone
uv run casefile jdoe-example --deep            # also run on-demand sources (bare, or a comma-separated list of ids)
uv run casefile --cases                        # list saved cases with their ids
uv run casefile --export <case-id> --format md|json|html
uv run casefile --clear-cache
uv run casefile --forget-cases
```

`--deep` and `--check-links` are opt-in because the egress is large: the WhatsMyName check queries several hundred
sites from your IP and takes 30-60s. The browser has the same two as buttons (**Run this check**, **Check for dead
links**) rather than panels that load themselves. Only 404 and 410 count as a dead link; blocked, redirected and
unreachable are reported as telling you nothing, because a checker that guessed would invent cleared leads.

## Checks

```bash
make check   # ruff check, ruff format --check, pytest. Exactly what CI runs.
make test    # pytest only
make fmt     # ruff format, ruff check --fix
make live    # pytest -m live: hits real third-party services, deselected by make test
make demo    # render the static demo into site/
```

Requires [uv](https://docs.astral.sh/uv/), which fetches its own Python.

## Adding a source

A data edit, not code: a `[[source]]` block in `src/casefile/catalog/<category>.toml` with `id`, `name`, `accepts`
(entity types) and an `https://` `url` containing `{value}`. `make test` validates every entry, and rejects a
duplicate id or a duplicate url for the same type (two rows going to one page is a difference that is not there).

A fetcher, ie a source casefile calls itself rather than links to, is a registration in
`src/casefile/fetchers/sources.py`.

## Constraints the tests enforce

Reversing one of these fails a test in `tests/test_constraints.py`, not by accident.

- No real host or dialable phone number in fixtures or in this README. Reserved only: `example.com`, RFC 5737,
  RFC 3849, `555-01xx` and the ACMA `5550 xxxx` ranges. It is an OSINT tool, so this matters more than usual.
- One `httpx.AsyncClient`, built in `fetchers/http.py`, so every request carries the same User-Agent and timeouts.
- The demo renders through the real templates with `demo=True`. A `demo_*.html` file is the fork coming back.
- No startup hook on the app: it would open a browser for every importer, including CI and `--build-demo`.
- `src/casefile/vendor/wmn-data.json` is vendored byte-for-byte under CC BY-SA. Never edit it; keep casefile-specific
  behaviour keyed off site names. See `src/casefile/vendor/README.md`.

Design and plan docs are in `docs/superpowers/`. Internal, and excluded from the sdist.

## What hits disk

Two SQLite stores, purged by different commands on purpose: a privacy purge must not destroy work you saved
deliberately.

| Store | Path | Lifetime | Purge |
| --- | --- | --- | --- |
| Response cache | `${XDG_CACHE_HOME:-~/.cache}/casefile/cache.db` | 24h, 5 min for failures | `--clear-cache` |
| Saved cases | `${XDG_DATA_HOME:-~/.local/share}/casefile/cases.db` | until deleted | `--forget-cases` |

The cache is keyed on the identifier searched, so it is in effect a local log of what you looked up, written whether
or not you star anything. Expired rows are swept on open, not on write. Both files are `0600` inside a `0700`
directory, and a purge unlinks the file plus its `-journal`/`-wal`/`-shm` siblings rather than deleting rows, which
would leave search terms readable in freed pages.

Fetching goes out over your own connection: every source sees your IP, and there is no proxy in this version.

## Cases

A case is an investigation, not one identifier: `jdoe-example` the username and `example.com` the domain are the same
subject to you and nothing alike to a detector.

- **Save this identifier** keeps a lead before anything on it is worth starring. Starring a finding also opens a case.
- An identifier lives in at most one case. Adding it to another moves it, findings included.
- A case is named after its first identifier and can be renamed on its page.
- Removing an identifier takes its findings with it, and removing the last one closes the case. Un-starring the last
  finding does not, because that is a change of mind about one row.

## Gotchas

- Panels load over `fetch`, so a content blocker that matches the request URL kills one. A blocked panel reads
  **failed** with an explanation rather than sitting on "loading…". Allow `127.0.0.1` in the blocker.
- MalwareBazaar is the one source needing a key: `ABUSECH_AUTH_KEY`, from the environment or a `.env` in the working
  directory (see `.env.example`). Without it that panel reads "needs a key" and nothing else changes.

## Demo and release

`make demo` builds a static prerender of the real templates against fixture data into `site/`. It cannot look anything
up. Publishing is manual, and `casefile.cpwillis.dev` is not deployed yet, so the repo homepage link is dead.

`.github/workflows/release.yml` is manual dispatch only: it runs `make check`, builds, asserts the wheel carries the
catalogue, the vendored dataset, the templates and the static assets, then publishes to PyPI via Trusted Publishing.
Tagging deliberately does not publish, since a PyPI version can never be re-uploaded. `ci.yml` and `live.yml` are
manual too.
