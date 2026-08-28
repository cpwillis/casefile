# casefile

One input box, every relevant OSINT pivot. Paste a domain, IP, email, username,
company, phone number, hash, vessel or aircraft identifier and casefile works out
what it is, then fans out across hundreds of public sources.

Runs on your machine. Nothing is hosted.

## Usage

```bash
uvx casefile
```

That is the whole thing. It prints a local URL and opens your browser on it:

```
casefile is running at http://127.0.0.1:8765
press ctrl-c to stop
```

From there you work in the browser. Paste a domain, an IP, an email, a username, a company
name, a phone number, a hash, a vessel or an aircraft identifier. casefile works out what it
could be and shows every relevant public source, links first.

Nothing is configured, nothing is uploaded, and no account is involved. Ctrl-C stops it.

Add `--no-browser` over SSH or on a headless box, and `--port` if 8765 is taken.

### What leaves your machine

casefile fetches live results over **your own connection**, so the sources you query see
your IP. There is no proxy in this version. Fetched results are cached locally for 24 hours
(see Status below); nothing leaves your machine beyond the direct requests to each source.
Pass `--no-cache` to bypass the cache for a single run.

A username search queries 687 sites, so it takes 30-60 seconds and is the single most
visible thing casefile does from your IP address.

## Local development

Clone it and run from source. Requires [uv](https://docs.astral.sh/uv/) (which fetches its
own Python, so nothing else to install):

```bash
git clone https://github.com/cpwillis/casefile
cd casefile
uv sync
uv run casefile
```

`uv run casefile` launches the local web app and opens your browser on it, the same as the
installed tool. Useful variants:

```bash
uv run casefile example.com          # print results to the terminal instead of the browser
uv run casefile example.com --json   # machine-readable, for piping
uv run casefile --no-browser         # start the server without opening a browser
uv run casefile example.com --no-cache   # bypass the response cache for this run
uv run casefile --clear-cache        # purge every cached response and exit
```

Run the checks (exactly what CI runs):

```bash
make check          # ruff lint + format check + pytest
make test           # pytest only
make fmt            # auto-format and auto-fix
```

The link catalogue lives in `src/casefile/catalog/*.toml`, one file per category. Adding a
source is a data edit: add a `[[source]]` block with an `id`, a `name`, the entity types it
`accepts`, and an `https://` `url` containing `{value}`. `make test` validates every entry.

## Demo

[casefile.cpwillis.dev](https://casefile.cpwillis.dev) is a static, deliberately
non-functional showcase built from real output against fixture data. It shows
what the tool does. It cannot look anything up. Run it locally for that.

## Status

v1.0.0. `EntityType` has 21 members; 20 of them have a detector (`plate` does not yet), plus a
250+ slot link catalogue. Live fetching comes from eight keyless sources (dns, rdap, crtsh,
internetdb, github, wikidata and hashlookup over the network, plus phone_meta offline) and the
687-site WhatsMyName username checker.

Responses are cached for up to 24 hours under `${XDG_CACHE_HOME:-~/.cache}/casefile/`, and
rows older than 24 hours are pruned on the next cache access regardless of whether they are
ever queried again. `casefile --clear-cache` deletes the cache file outright and purges
everything immediately; `--no-cache` bypasses the cache for a single run. Both are privacy
controls as much as debugging ones.

One source needs a key: MalwareBazaar requires a free `ABUSECH_AUTH_KEY` (see `.env.example`).
Without it that panel reads "needs a key" and everything else works normally.

See [docs/superpowers](docs/superpowers).

## Licence

MIT, see [LICENSE](LICENSE). The WhatsMyName dataset vendored under
`src/casefile/vendor/wmn-data.json` is by Micah Hoffman and contributors, licensed CC BY-SA
4.0: https://github.com/WebBreacher/WhatsMyName. See
[src/casefile/vendor/README.md](src/casefile/vendor/README.md) for details. Any further
third-party datasets vendored later keep their own licences and attribution.
