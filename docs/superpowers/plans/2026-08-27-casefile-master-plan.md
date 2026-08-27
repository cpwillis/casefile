# casefile master plan

**Goal:** Sequence casefile from an empty repo to v1.0 across four phases, and settle the
decisions that cut across all of them so they are not made four times inconsistently.

**Scope:** This is the programme plan. It does not contain tasks. Each phase gets its own
task-level implementation plan under `docs/superpowers/plans/`, written immediately before
that phase starts, not now: writing phase 4's tasks before phase 1 exists would be
fiction.

**Spec:** [2026-08-27-casefile-design.md](../specs/2026-08-27-casefile-design.md)

**Status:** phase 1 blocked on one open decision. See Blockers.

---

## Global constraints

Copied verbatim from the spec. Every phase plan inherits these without restating them.

- Python `>=3.12`.
- Five runtime dependencies, total, named: `httpx`, `starlette`, `uvicorn`, `jinja2`,
  `phonenumbers`. Adding a sixth is a decision, not an implementation detail.
- Each dependency is added to `pyproject.toml` by the phase that first imports it. The
  declared list is never aspirational.
- MIT, copyright holder `cpwillis`. No GPL code imported; any GPL tool is subprocessed.
- Catalogue is TOML, parsed with stdlib `tomllib`.
- Exactly one positional value on the CLI. No `--input-file`, no target lists, no batch
  mode, ever.
- No query log, no telemetry. The response cache is the only thing written to disk.
- Web app binds `127.0.0.1` only.
- Every outbound request sends
  `User-Agent: casefile/<version> (+https://github.com/cpwillis/casefile)`.
- Fixtures contain no real person's data. Reserved ranges only: `example.com`,
  RFC 5737, RFC 3849.
- Commits are bare lowercase one-line, linear, GPG-signed.

---

## Phase sequence

One deviation from the spec, deliberate: **the demo moves from last to second.**

The demo does not depend on fetchers. After phase 1 the tool genuinely is a link
dispatcher, so a links-only demo is an honest representation of it, not a stub. Shipping
it second gets `casefile.cpwillis.dev` live weeks earlier, and every later phase then
improves the site for free because the demo is a prerender of whatever the app currently
does.

| Phase | Deliverable | Release | Depends on |
|---|---|---|---|
| 1 | Detection, catalogue, link rendering, CLI. No network. | `0.1.0` | Layout decision |
| 2 | Demo build and deploy, links-only | `0.2.0` | Phase 1, Cloudflare access |
| 3 | Fetcher registry, rate limiting, first three fetchers | `0.3.0` | Phase 1 |
| 4 | Remaining five fetchers, WhatsMyName, SQLite cache | `1.0.0` | Phase 3 |

The demo is rebuilt and redeployed at the end of phases 3 and 4. That is one command, not
a phase.

Phases 2 and 3 are independent of each other and could run in either order. Phase 2 first
is recommended: a live public site is worth more than three fetchers, and it puts the
project somewhere findable while the interesting work continues.

### Which phase owns which spec section

Every spec section maps to exactly one phase, so nothing cross-cutting is orphaned.

| Spec section | Phase |
|---|---|
| Entity detection, ranking, normalisation | 1 |
| Catalogue data model, validation | 1 |
| Web application, CLI, repo layout | 1 |
| `ci.yml` (lint + tests + demo smoke) | 1 |
| Static demo, fixture data rules and PII test | 2 |
| `demo.yml`, `release.yml`, Trusted Publishing | 2 |
| Contribution surface | 2 |
| Fetcher registry, rate limiting, panel states, result model | 3 |
| Request conduct: User-Agent, jitter, retry policy | 3 |
| WhatsMyName checker and its UI attribution | 4 |
| SQLite cache, `--no-cache`, `--clear-cache` | 4 |

`ci.yml` lands in phase 1 rather than phase 2. Tests without CI is a habit that does not
survive the second week.

### Release meaning

- `0.0.0` is the published placeholder holding the PyPI name. Permanently spent.
- `0.1.0` is the first real release and is genuinely useful on its own: paste an
  identifier, get every relevant pivot as a link, with zero network calls.
- `1.0.0` requires phase 4 complete **and** the catalogue at 250+ type-slots. Version 1.0
  claims coverage, so it should not be cut on 100 entries.

---

## Cross-cutting decision 1: catalogue seeding

The largest single body of work in the project, and the spec says only "seeded broadly".
Settled here.

### What cannot be automated

awesome-osint and its siblings list *which tools exist* and link their homepages. They do
not contain query templates, which is the only part casefile needs. There is no dataset to
import for anything except usernames.

So templates are authored by hand: open the site, run a real search, copy the resulting
URL, substitute `{value}`. Roughly two to three minutes per entry once you have a rhythm.

Honest arithmetic: **100 type-slots is about four hours of grind. 400 is about sixteen.**
Nobody should discover that halfway through phase 1.

### What is already free

WhatsMyName supplies 700 username sites as vendored data. `username` needs no manual
seeding at all, which is why it is the one type deliberately absent from the allocation
below.

### Phase 1 seeding target

Coverage is measured in **type-slots**, not entries. An entry accepting three types fills
three slots, so roughly 70 to 80 unique entries deliver the ~110 slots below.

| Type | Slots | Type | Slots |
|---|---|---|---|
| `domain` | 12 | `coordinates` | 4 |
| `ip` | 10 | `eth_address` | 3 |
| `email` | 8 | `mac` | 3 |
| `person` | 8 | `vin` | 3 |
| `company` | 8 | `plate` | 3 |
| `phone` | 5 | `mmsi` | 3 |
| `hash` | 5 | `imo` | 3 |
| `url` | 5 | `icao24` | 3 |
| `cve` | 4 | `tail_number` | 3 |
| `asn` | 4 | `username` | via WMN |
| `btc_address` | 4 | | |

Minimum three per type is the rule from the spec: fewer than three and the type has
nowhere useful to send you, so it should not ship.

### Growth after phase 1

Via pull request, which is why the contribution surface below matters. The validation test
is the gate, so a bad entry cannot merge. Target for `1.0.0` is 250 slots, reached by
accretion rather than by another grind session.

---

## Cross-cutting decision 2: contribution surface

The catalogue is the contribution magnet: adding a source is a data edit, so the skill
floor is low and the review cost is near zero. That only works if the surface is built
before the repo gets attention, which is phase 2, when the site goes live.

Required by end of phase 2:

- `CONTRIBUTING.md` containing the entry-authoring procedure step by step, the
  three-slots-minimum rule, the `provenance` convention, and an explicit statement that
  sources requiring an account are still welcome as link entries.
- A pull request template whose body is a checklist: entry validates, URL tested by hand,
  `accepts` types correct, no PII in any example.
- `casefile check-links` documented as the thing to run before submitting a batch.
- The validation test running on every PR, so review is "did CI pass and is the URL real"
  rather than a schema argument.

Deliberately not doing: a web form for submissions, a bot that auto-opens PRs from
upstream lists, or a scoring system for sources. All three are solutions to a contributor
volume this project does not have.

---

## Cross-cutting decision 3: CI/CD

Three workflows, no more.

**`ci.yml`** on push and pull request:
`ruff check`, `ruff format --check`, `pytest`, then `casefile build-demo` as a smoke test.
No link checking, for the reason the spec gives: firing 400 requests at other people's
services on every push is flaky and rude.

**`demo.yml`** on push to `main`:
build the demo, deploy `dist/` to Cloudflare. Needs a scoped Cloudflare API token in
repository secrets. Set up in phase 2.

**`release.yml`** on tag `v*`:
build and publish to PyPI via **Trusted Publishing**, not an API token. Configured once in
phase 2, which retires the account-wide token used for `0.0.0`.

Note on test scope, stated because it is easy to misread: fetcher tests use recorded
responses, so they verify *parsing*, not that a source is still alive or still keyless.
Upstream drift is invisible to CI by design. Re-verification is a manual step at the start
of phases 3 and 4.

---

## Blockers

Resolve before the phase that needs it. Nothing else is unresolved.

**Blocking phase 1: result page layout.**
The one design question the spec deliberately declines to answer in prose, because it is
visual. Phase 1's deliverable is a rendered page, so this cannot be deferred past it.

**Blocking phase 2: Cloudflare setup.** DNS for `casefile.cpwillis.dev`, the
`osint.cpwillis.dev` 301 redirect rule, and a scoped API token in repository secrets.
Owner-performed.

**Blocking phase 4 (soft): source re-verification.** Confirm all eight fetcher sources are
still keyless and free. Free tiers move, and the spec says to re-check at implementation
time rather than trusting the table.

**Not blocking anything: Mitaka and Sputnik licences.** Only relevant if bulk-ingesting
their template sets, which the seeding strategy above does not depend on. Manual authoring
is the plan; those sets are an optional accelerator that needs a licence check first.

---

## Risks

| Risk | Reality | Mitigation |
|---|---|---|
| Catalogue rot | URLs and query formats change constantly. Some fraction is always broken. | `check-links` run by hand; PRs fix drift; accept rot as the steady state rather than engineering against it |
| Source API drift | Recorded-response tests cannot see it | Manual re-verification at phase 3 and 4 start; a broken fetcher degrades to one dead panel, never a failed page |
| WMN format change | Would break the username checker | Vendored file is pinned. Updating is a deliberate act, so this can never break unannounced |
| A free tier closes | Loses one of eight fetchers | Backlog holds verified alternatives per entity type |
| Becomes a doxxing vector | The capability is real | Local-only, no bulk input, no telemetry, honest User-Agent. All architectural, not policy |
| Scope creep back to graph and monitoring | The interesting-but-wrong direction | Non-goals are explicit; the audit precedent is in the history |
| Single maintainer stalls | Most likely failure mode by far | Catalogue is data, so contribution requires no Python; MIT means a fork costs nothing |
| Seeding grind is abandoned midway | Four hours is easy to underestimate and easy to quit | Three-slots-per-type minimum makes partial progress shippable; `0.1.0` does not require 400 entries |

---

## Definition of done, v1.0

- All four phases complete with their acceptance criteria met.
- Catalogue at 250+ type-slots, every one of the 21 types at three or more.
- Eight fetchers plus the WhatsMyName checker returning typed `SourceResult`s.
- `uvx casefile` works from a clean machine with no system dependencies.
- `casefile.cpwillis.dev` live, prerendered from the real app, containing no live endpoint
  references, navigable without JavaScript.
- `osint.cpwillis.dev` 301s to it.
- `CONTRIBUTING.md` and the PR template in place.
- Trusted Publishing configured; no long-lived PyPI token exists.
- README states plainly: runs locally, uses your own IP, caches third-party data,
  `--clear-cache` purges it, the operator is responsible for the lookups they run.

## Explicitly after v1.0

Recorded so they are not relitigated as if new: scheduled monitoring and change-diffing,
proxy and Tor egress, a Docker profile wrapping the Go tools, entity resolution and a
graph, report export beyond JSON.

Each would be its own spec. None is a v1 concern.

---

## Next step

Write `docs/superpowers/plans/2026-08-27-casefile-phase-1.md` as a task-level plan, once
the layout blocker is resolved.
