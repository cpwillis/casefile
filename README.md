# casefile

One input box, every relevant OSINT pivot. Paste a domain, IP, email, username,
company, phone number, hash, vessel or aircraft identifier and casefile works out
what it is, then fans out across hundreds of public sources.

Runs on your machine. Nothing is hosted.

```bash
uvx casefile
```

## Demo

[casefile.cpwillis.dev](https://casefile.cpwillis.dev) is a static, deliberately
non-functional showcase built from real output against fixture data. It shows
what the tool does. It cannot look anything up. Run it locally for that.

## Status

Planning. See [docs/superpowers/specs](docs/superpowers/specs).

## Licence

MIT, see [LICENSE](LICENSE). Third-party datasets under `vendor/` keep their own
licences and attribution.
