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

Add `--no-browser` on a headless box, and `--port` if 8765 is taken.

casefile binds `127.0.0.1` and has no flag to bind anything else, on purpose. To reach it on a
remote machine, forward the port rather than exposing it:

```bash
ssh -L 8765:127.0.0.1:8765 you@box   # then open http://127.0.0.1:8765 locally
```

### Saving what you find

Star a finding and casefile keeps it, or use **Save this search** to keep a lead before anything
on it is worth starring. A case holds as many identifiers as you put in it, so reopening the app
shows the investigation you were working on rather than an empty box. Export a case as Markdown,
JSON or a self-contained HTML file.

```bash
casefile --cases                          # list saved cases
casefile --cases                          # list them, with their case ids
casefile --export <case-id>               # markdown to stdout
casefile --export <case-id> --format json
casefile --forget-cases                   # delete them all
```

Everything stays on this machine; nothing is ever uploaded. Two things reach disk, and they are
different in kind, so they are purged by different commands:

- **The response cache** is keyed on the identifier you searched, so for 24 hours it is in effect
  a local log of what you looked up, written automatically whether or not you star anything.
  `casefile --clear-cache` removes it.
- **Saved cases** hold the identifiers you saved and the findings you starred against them, and
  are kept until you delete them. `casefile --forget-cases` removes them all, or delete one from
  its page.

A privacy purge must never destroy the work you deliberately saved, which is why clearing the
cache leaves your cases alone.

### What leaves your machine

casefile fetches live results over **your own connection**, so the sources you query see
your IP. There is no proxy in this version. Fetched results are cached locally for 24 hours
(see Status below); nothing leaves your machine beyond the direct requests to each source.
Pass `--no-cache` to bypass the cache for a single run.

A username search can query several hundred sites and take 30-60 seconds, so it is opt-in:
in the browser it is a "Run this check" button on the results page rather than a panel that
loads itself, and on the CLI it only runs when you pass `--deep`.

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
uv run casefile octocat --deep       # also run on-demand sources (the username checker)
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
251-slot link catalogue. Live fetching comes from eight keyless sources (dns, rdap, crtsh,
internetdb, github, wikidata and hashlookup over the network, plus phone_meta offline) and the
WhatsMyName username checker, which queries several hundred sites from your IP and is opt-in
(the browser button, or `--deep` on the CLI) rather than run automatically. The link lists carry
the same kind of opt-in check: **Check which of these exist** probes each link once and marks the
ones that are definitely not there. Only 404 and 410 count as missing; bot protection, redirects
and timeouts are reported as telling you nothing, because a checker that guessed would invent
cleared leads.

Answers are cached for up to 24 hours under `${XDG_CACHE_HOME:-~/.cache}/casefile/`, and rows
older than that are pruned on the next cache access whether or not they are ever queried again.
Failures are cached too, but for five minutes rather than a day: long enough that reloading a
page does not re-hammer a source that just returned a 502, short enough that an outage clears
itself. Reopening a search you have already run paints from the cache with the page, so only
genuinely unknown sources go out to the network. Every panel carries a **refresh** control that
ignores the stored answer and replaces it. `casefile --clear-cache` deletes the cache file
outright; `--no-cache` bypasses it for a single run without writing anything. Both are privacy
controls as much as debugging ones.

## Cases

A case is an investigation, not a single identifier. `acme-example` the username and
`acme.example` the domain are the same subject to you and nothing alike to a detector, so a
case holds as many identifiers as you put in it and shows up once on the dashboard.

- **Save this search** on any reading keeps it, whether or not anything on the page is yet worth
  starring. Starring a finding also starts a case, so the quick path stays one click.
- Already have a case? The same control adds the search to it instead. An identifier lives in at
  most one case, so joining moves it, findings included.
- A case is named after the first identifier saved into it and can be renamed on its page.
- Removing an identifier takes its findings with it. Removing the last one closes the case;
  un-starring the last finding does not, because that is a change of mind about one row.

## Content blockers

Panels load over `fetch`, so a content blocker that matches the request URL can stop one without
the page noticing. casefile now says so: a blocked panel reads **failed** with an explanation
rather than sitting on "loading…". If you see that, allow `127.0.0.1` in your blocker, or check
its request log to see which filter matched. The long-running WhatsMyName check also shows a
"running…" line while it works, so a slow check no longer looks like a dead button.

One source needs a key: MalwareBazaar requires a free `ABUSECH_AUTH_KEY` (see `.env.example`).
Without it that panel reads "needs a key" and everything else works normally.

See [docs/superpowers](docs/superpowers).

## Licence

MIT, see [LICENSE](LICENSE). The WhatsMyName dataset vendored under
`src/casefile/vendor/wmn-data.json` is by Micah Hoffman and contributors, licensed CC BY-SA
4.0: https://github.com/WebBreacher/WhatsMyName. See
[src/casefile/vendor/README.md](src/casefile/vendor/README.md) for details. Any further
third-party datasets vendored later keep their own licences and attribution.
