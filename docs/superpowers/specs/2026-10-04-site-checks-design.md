# Site checks: passive panels and an opt-in site visit

Reference: lissy93/web-check (MIT), used for which checks exist, not for code. Reimplemented in Python against the
existing fetcher registry. No new dependencies.

## Principle

casefile has never contacted the target: every fetcher asks a third party about it. That stays the default. Checks
that must touch the target sit behind one explicit click per reading, and the click is the only path that runs them.

## Phase A: passive fetchers

Ordinary `@fetcher` registrations, auto-loading like the existing panels. None contacts the target.

| id | accepts | source | findings |
|---|---|---|---|
| `mail` | domain | Cloudflare DoH: TXT on the domain, `_dmarc.`, `_mta-sts.`, `default._bimi.` | SPF policy and includes, DMARC policy and rua/ruf, MTA-STS present, BIMI present |
| `dnssec` | domain | Cloudflare DoH, `type=DS`, `do=1` | signed or not, validated (AD flag), DS algorithm |
| `wayback` | domain, URL | Wayback CDX API, `limit=1` and `limit=-1` | first and last capture, link to the calendar |
| `tranco` | domain | tranco-list.eu ranks API | latest rank and date, direction over the returned window |
| `hsts-preload` | domain | hstspreload.org `api/v2/status` | preload status |
| `ip-geo` | IP | ipwho.is | country, region, city, ASN, org, connection type |
| `urlhaus` | domain, URL, IP | URLhaus host and url endpoints | URL count, status, threat, tags; needs `ABUSECH_AUTH_KEY` |
| `blocklists` | domain | AdGuard, Cloudflare Security, Cloudflare Family DoH, unfiltered Cloudflare as control | which resolvers block it |

- Quad9 is excluded: JSON DoH unavailable, wire format only.
- Wayback measured 9s and 17s per call; the fetcher gets its own 40s budget. The 24h cache pays it once.
- URLhaus answers 401 without a key: the panel reads "needs a key", like MalwareBazaar.
- A blocklist verdict needs the control: blocked means the filtered resolver returns NXDOMAIN or a sinkhole
  (`0.0.0.0`, `::`) while the control resolves. If the control itself fails or is NXDOMAIN, the result is "cannot tell".

## Phase B: the site visit

Three fetchers registered with a new `contacts_target=True` field, accepting domain and URL. Split by request, so
nothing is fetched twice and each fails on its own.

- `site-http`: one `GET` of `https://<domain>/`, or exactly the URL for a URL reading. Final status, time to first
  byte, redirect chain, security headers present or missing with values (HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP), cookie names with `Secure`/`HttpOnly`/`SameSite`,
  tech hints labelled as hints (Server, X-Powered-By, generator meta, CDN headers, known cookie names), OpenGraph and
  Twitter tags via stdlib `html.parser`.
- `site-tls`: one stdlib `ssl` handshake on 443 with SNI. Verified: issuer, subject, SANs, validity window, days left,
  protocol, cipher. Verification failure is the finding (the `ssl` reason, eg "certificate has expired"), with
  protocol and cipher from an unverified retry. Leaf only: the chain needs 3.13's `get_verified_chain`.
- `site-files`: `robots.txt` (present, disallow count, declared sitemaps, first disallowed paths), `sitemap.xml`
  (present, URL count), `/.well-known/security.txt` (Contact, Expires, Policy, signed). 404 reads as absent.

Never shown: cookie values. They are often session tokens, and findings can be saved and exported.

### Consent

- `contacts_target` is separate from `on_demand`. `on_demand` means large egress; `contacts_target` means the
  target sees you. They have separate triggers.
- Web: each domain or URL reading with visit panels renders one block with a "Visit the site" button, the note
  "about 5 requests to <host> from your IP; the site will see them", and three placeholders listening for one event
  from the block. Cached results render prefilled; a visit in flight is joined.
- CLI: `--visit` runs them. Bare `--deep` never does. Text output without the flag lists them with the hint.
- No resume: visit runs write no job row, so a restart never contacts the target unprompted.
- A constraint test asserts no path runs a `contacts_target` fetcher without its trigger: page load, `--deep`,
  `resume_jobs`.

### Egress safety

- Redirects walked by hand, max 5. Every hop's host is resolved first; any non-global address refuses the hop.
- TLS connects to the checked address with `server_hostname` set, so DNS cannot change between check and connect.
- Same shared client (one-client constraint). Per-request headers for visits only: UA from
  `CASEFILE_VISIT_USER_AGENT` (env or `.env`), default a current Chrome string, plus browser `Accept` and
  `Accept-Language`. Third-party APIs keep the casefile UA.
- The 4 MB body cap applies.

## Testing

- Each fetcher: MockTransport for the answer shape, empty, error and rate-limit paths.
- Visit: private resolution refused, redirect to a private host refused, redirect chain reported, cookie values
  absent from findings, no job row written, `--deep` does not run it, `--visit` does, the page renders the block
  with one trigger.
- One live test per new keyless source in `tests/test_live_sources.py`, deselected by default.

## Docs

- README: the target never sees you unless you click Visit the site or pass `--visit`; the new flag; the env var.
- `.env.example`: `CASEFILE_VISIT_USER_AGENT`.
- Demo: canned passive panels for `example.com`; visit panels read "not in this demo".

## Out

Port scanning, traceroute, screenshots, tech-stack via headless Chromium, tracker lists, PageSpeed, Shodan full,
HIBP, crawling linked pages, carbon estimates. Reasons: active scanning of a host the user does not own, system
binaries, dependency budget, paid keys, or the one-request-per-site rule.
