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

v0.1.0: detection, catalogue and browser UI, links only, no network calls yet.
Live source fetching lands in a later phase. See [docs/superpowers](docs/superpowers).

## Licence

MIT, see [LICENSE](LICENSE). Any third-party datasets vendored later keep their own
licences and attribution.
