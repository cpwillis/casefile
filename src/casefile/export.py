"""One saved case to Markdown, JSON or self-contained HTML. Never re-fetches: a case is what you kept, not a scrape."""

import json
from dataclasses import asdict
from datetime import UTC, datetime
from html import escape
from itertools import groupby

from casefile.cases import Case
from casefile.fetchers import source_note
from casefile.fetchers.wmn import CREDIT, CREDIT_URL, SOURCE_ID

_SAFE_SCHEMES = ("https://", "http://")

_HTML_CSS = """
:root { color-scheme: light dark; }
body { font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; max-width: 46rem; margin: 3rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; margin-bottom: .2rem; }
h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .05em; margin-top: 2rem; }
h3 { font-size: .9rem; color: #6b6b6b; margin: 1.2rem 0 .3rem; }
.meta { color: #6b6b6b; font-size: .85rem; margin-top: 0; }
ul { list-style: none; padding: 0; }
li { display: flex; gap: .75rem; padding: .2rem 0; border-bottom: 1px solid rgba(128,128,128,.2); }
.label { color: #6b6b6b; min-width: 8rem; }
"""


def sanitize(text: str, keep: str = "") -> str:
    """Escape non-printable third-party characters. Escaped not dropped: deleting a zero-width turns paypa<zwsp>l
    into the name it imitates. Shared by the CLI's terminal output and every export, so a download is safe too."""
    return "".join(ch if ch.isprintable() or ch in keep else ch.encode("unicode_escape").decode("ascii") for ch in text)


def when(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _md(text: str) -> str:
    """Escape a third-party value for Markdown: unescaped, ] or ( breaks out of link syntax and raw HTML survives."""
    for char in ("\\", "`", "*", "_", "[", "]", "(", ")", "<", ">", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text.replace("\r", " ").replace("\n", " ")


def safe_url(url: str | None) -> str | None:
    """A url is a link only with an allowed scheme and no whitespace or controls, which no real url has and which
    would break out of a Markdown link or an HTML attribute. The one gate the exporter and the Jinja filter share."""
    if url and url.lower().startswith(_SAFE_SCHEMES) and url.isprintable() and " " not in url:
        return url
    return None


def _credit(case: Case) -> bool:
    """CC BY-SA wants attribution where used, and an export is the one artifact that leaves without the licence."""
    return any(s.source_id == SOURCE_ID for s in case.stars)


def _by_target(case: Case):
    """Findings grouped as the case is: identifier first, then source, because a flat list mixes unrelated targets."""
    ordered = sorted(case.stars, key=lambda s: (s.target_type, s.target_value, s.source_id, s.label, s.value))
    for target, rows in groupby(ordered, key=lambda s: (s.target_type, s.target_value)):
        yield target, groupby(rows, key=lambda s: s.source_id)


def _summary(case: Case) -> str:
    return (
        f"{len(case.targets)} identifier{'s' if len(case.targets) != 1 else ''}"
        f" · {case.star_count} saved · case last edited {when(case.updated_at)}"
    )


def _to_markdown(case: Case) -> str:
    lines = [f"# {_md(case.name)}", "", _md(_summary(case))]
    if case.targets:
        lines += ["", "## Identifiers", ""]
        lines += [f"- `{_md(t.entity_type)}` {_md(t.value)} ({t.star_count} saved)" for t in case.targets]
    for (target_type, target_value), sources in _by_target(case):
        lines += ["", f"## {_md(target_value)}", "", f"`{_md(target_type)}`"]
        for source_id, stars in sources:
            lines += ["", f"### {_md(source_id)}", ""]
            if note := source_note(source_id):  # the polarity caveat: a known-good hit and a malware hit look alike
                lines += [f"_{_md(note)}_", ""]
            for s in stars:
                url = safe_url(s.url)
                # Parens are legal in a url but close a Markdown link early, letting a crafted second link in.
                link = url.replace("(", "%28").replace(")", "%29") if url else None
                rendered = f"[{_md(s.value)}]({link})" if link else _md(s.value)
                seen = f" _(saved {_md(when(s.starred_at))})_" if s.starred_at else ""
                lines.append(f"- **{_md(s.label)}**: {rendered}{seen}")
    lines += ["", "---", "", "Exported by casefile. Only starred findings are included."]
    if _credit(case):
        lines += ["", f"{_md(CREDIT)} {CREDIT_URL}"]
    return "\n".join(lines) + "\n"


def _to_json(case: Case) -> str:
    """asdict, not a hand-copied subset: a hand-written payload drifts below what the other renderers show."""
    payload = asdict(case)
    if _credit(case):
        payload["attribution"] = [{"text": CREDIT, "url": CREDIT_URL}]
    return json.dumps(payload, indent=2)


def _to_html(case: Case) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{escape(case.name)} — casefile</title>",
        f"<style>{_HTML_CSS}</style>",
        "</head><body>",
        f"<h1>{escape(case.name)}</h1>",
        f'<p class="meta">{escape(_summary(case))}</p>',
    ]
    if case.targets:
        parts.append("<h2>Identifiers</h2><ul>")
        for t in case.targets:
            parts.append(
                f'<li><span class="label">{escape(t.entity_type)}</span>'
                f"<span>{escape(t.value)} ({t.star_count} saved)</span></li>"
            )
        parts.append("</ul>")
    for (target_type, target_value), sources in _by_target(case):
        parts.append(f'<h2>{escape(target_value)} <span class="meta">{escape(target_type)}</span></h2>')
        for source_id, stars in sources:
            parts.append(f"<h3>{escape(source_id)}</h3>")
            if note := source_note(source_id):
                parts.append(f'<p class="meta">{escape(note)}</p>')
            parts.append("<ul>")
            for s in stars:
                url = safe_url(s.url)
                value = (
                    f'<a href="{escape(url)}" rel="noreferrer noopener">{escape(s.value)}</a>'
                    if url
                    else escape(s.value)
                )
                seen = f'<span class="meta"> saved {escape(when(s.starred_at))}</span>' if s.starred_at else ""
                parts.append(f'<li><span class="label">{escape(s.label)}</span><span>{value}{seen}</span></li>')
            parts.append("</ul>")
    parts.append('<p class="meta">Exported by casefile. Only starred findings are included.</p>')
    if _credit(case):
        parts.append(
            f'<p class="meta">{escape(CREDIT)} '
            f'<a href="{CREDIT_URL}" rel="noreferrer noopener">{escape(CREDIT_URL)}</a></p>'
        )
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


# One place a format is declared, renderer and media type together, so the download route cannot type one differently.
_RENDERERS = {
    "md": (_to_markdown, "text/markdown; charset=utf-8"),
    "json": (_to_json, "application/json"),
    "html": (_to_html, "text/html; charset=utf-8"),
}
FORMATS = tuple(_RENDERERS)


def media_type(fmt: str) -> str:
    return _RENDERERS[fmt][1]


def export_case(case: Case, fmt: str) -> str:
    try:
        render = _RENDERERS[fmt][0]
    except KeyError:
        raise ValueError(f"unknown export format {fmt!r}, expected one of {', '.join(FORMATS)}") from None
    # keep \n\t: they are the structure of md and html. json is already ascii-escaped by json.dumps, so this is a no-op.
    return sanitize(render(case), keep="\n\t")
