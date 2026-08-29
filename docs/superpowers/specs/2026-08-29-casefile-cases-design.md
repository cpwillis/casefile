# casefile cases, export and UX design

Date: 2026-08-29
Status: approved (decisions delegated), pre-implementation

## Summary

casefile gains persistent user-owned state for the first time. You star findings while
investigating, they are kept in a case per target, and reopening the app shows the cases you
were working on. A case can be exported as Markdown, JSON or a self-contained HTML file.

Three subsystems, built in this order: **cases** (persistence), **export**, then **UX**.

## The decisions, and why

Delegated to me. Recorded here so they can be reversed knowingly.

| Decision | Choice | Why |
|---|---|---|
| Granularity | Nested: a case per target, with starred findings inside | The unit you return to is the target; the thing worth keeping is the specific finding. Either alone loses half of it. |
| What persists | **Only what you starred**, plus the target | This is what "favourite" means. It also keeps the permanent disk footprint to a short list you chose, rather than everything 700 sites said about a person. |
| Storage | SQLite at `${XDG_DATA_HOME:-~/.local/share}/casefile/cases.db` | Separate file, separate directory, separate lifecycle from the cache. XDG is explicit that cache is disposable and data is not. |
| Purge | `--clear-cache` keeps its current meaning and never touches cases. Cases are deleted individually, or wholesale with `--forget-cases` | A privacy control that silently destroyed your saved work would be a trap. Two stores, two commands, two meanings. |
| Export formats | Markdown, JSON, self-contained HTML | Markdown to paste into a report, JSON to pipe, HTML to keep or send. All three are a few lines each from one render model. |

### The guarantee this changes

The spec currently says:

> **No query log and no telemetry, ever.** Nothing about what was searched is written to disk
> beyond the response cache, which `--clear-cache` purges.

That is no longer true, and pretending otherwise would be worse than changing it. The amended
guarantee is:

> **No query log and no telemetry, ever.** casefile records nothing about what you searched
> unless you explicitly star it. Two things reach disk: a 24-hour response cache
> (`--clear-cache`), and the cases you deliberately saved (`--forget-cases`). Nothing is sent
> anywhere.

The distinction that matters is **deliberate versus automatic**. A tool that quietly logged every
search would be a surveillance risk on a shared machine. A tool that keeps the six things you
clicked a star on is a notebook. The feature is fine; the wording had to catch up.

### The other guarantee this changes

The spec also says:

> The web app is GET-only with no mutating routes, so there is no CSRF surface to defend.

Starring is a mutation, so that stops being true. Mitigations, all of which must hold:

- Mutating routes are **POST only**. A GET can never change state.
- Every mutating route rejects a request whose `Sec-Fetch-Site` is anything other than
  `same-origin`. Note this is stricter than the existing panel guard, which only rejects
  `cross-site`: for a mutation, a missing header is refused too, because the only legitimate
  caller is the app's own page.
- The app still binds `127.0.0.1` only.

A page you visit while casefile is running must not be able to write to your case file.

## Architecture

```
star a finding  ->  POST /star            ->  cases.db
                                              |
open the app    ->  GET /                 <---+  recent cases
open a case     ->  GET /case/{id}        <---+  target + starred findings
export a case   ->  GET /case/{id}/export.{md,json,html}
```

`cases.py` owns the store and knows nothing about HTTP. `export.py` turns a case into text and
knows nothing about storage. The web layer wires them together. Each is testable alone.

### Modules

- `casefile.cases` — the `Case` and `Star` dataclasses, the SQLite store, and its queries.
- `casefile.export` — one case to Markdown, JSON or HTML.
- `casefile.web.app` — three new routes plus the star endpoint.
- `casefile.cli` — `--cases`, `--export`, `--forget-cases`.

## Data model

```sql
CREATE TABLE cases (
    id          TEXT PRIMARY KEY,   -- stable slug: "<entity_type>:<value>"
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE stars (
    case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_id  TEXT NOT NULL,
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    url        TEXT,
    starred_at REAL NOT NULL,
    PRIMARY KEY (case_id, source_id, label, value)
);
```

The case id is derived, not random: `domain:example.com`. Starring the same finding twice is a
no-op rather than a duplicate, which is why the whole finding is the primary key. A case is
created implicitly by the first star and removed when its last star goes, so there are no empty
cases to tidy up.

`ON DELETE CASCADE` needs `PRAGMA foreign_keys = ON` per connection; SQLite defaults it off.

## Web surface

| Route | Method | Purpose |
|---|---|---|
| `/star` | POST | Star or unstar one finding. Returns the replacement button. |
| `/cases` | GET | All saved cases, most recently updated first. |
| `/case/{case_id}` | GET | One case: target and its starred findings. |
| `/case/{case_id}/export.{fmt}` | GET | Download as `md`, `json` or `html`. |

Starring is an htmx `hx-post` on a button inside each finding row, swapping itself for its own
opposite. No page reload, no JavaScript beyond htmx.

The index page gains a **recent cases** list when any exist. That is the "where I left off"
requirement: opening casefile shows what you were working on rather than an empty box.

## Export

One function per format over the same `Case`. Markdown is the default because it pastes into an
issue or a report unchanged.

- **Markdown** — target, when saved, then findings grouped by source, links as links.
- **JSON** — the case verbatim, for piping. Stable key names, same contract discipline as the CLI.
- **HTML** — one self-contained file with inline CSS, openable anywhere, no assets.

Export never re-fetches. It renders what you starred, which is the point: it is a record of what
you chose to keep, not a fresh scrape.

## UX changes

Deliberately small and each earning its place. No redesign.

1. **Recent cases on the index.** The landing page stops being an empty prompt.
2. **A result summary line.** `4 sources, 12 findings, 1 empty, 1 timeout` above the panels, so
   the shape of the result is legible before reading it.
3. **A star button per finding**, and a filled star when already saved.
4. **Copy button on finding values.** Copying an identifier out to paste elsewhere is the single
   most common physical action in this tool.
5. **`/` focuses the search box.** One keystroke, twelve lines of JavaScript at most.

Explicitly not doing: theming controls, a settings page, drag-to-reorder, tags, or full-text
search over cases. Each is plausible and none is needed to make the tool better today.

## Testing

- `cases.py`: create, star, unstar, idempotent re-star, cascade on last unstar, isolation via
  `XDG_DATA_HOME`.
- `export.py`: one test per format asserting the starred finding appears and no unstarred data
  leaks in.
- Constraint tests, the category that defends decisions rather than behaviour:
  - `--clear-cache` must leave cases intact. This is the trap the two-store design exists to
    avoid, so it gets an explicit test.
  - A mutating route must refuse a cross-site request **and** a request with no
    `Sec-Fetch-Site` header.
  - No mutating route responds to GET.
- Tests never touch the real `~/.local/share/casefile`, the same discipline the cache tests use.

## Out of scope

Phase 2's demo build is separate work, though it now has one more thing to handle: the demo has
no backend, so star buttons must render inert rather than dangling. Deployment and the PyPI
release are explicitly last and are not part of this.
