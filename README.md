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

## Demo

[casefile.cpwillis.dev](https://casefile.cpwillis.dev) is a static, deliberately
non-functional showcase built from real output against fixture data. It shows
what the tool does. It cannot look anything up. Run it locally for that.

## Status

Planning. See [docs/superpowers/specs](docs/superpowers/specs).

## Licence

MIT, see [LICENSE](LICENSE). Third-party datasets under `vendor/` keep their own
licences and attribution.
