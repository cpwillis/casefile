"""Turn one saved case into Markdown, JSON or a self-contained HTML file.

Export renders what you starred and nothing else. It never re-fetches: a case is a record of
what you chose to keep, not a fresh scrape, so exporting an old case cannot quietly reach out
to twenty third parties.
"""

import json
from datetime import UTC, datetime
from html import escape
from itertools import groupby

from casefile.cases import Case
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


def when(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _md(text: str) -> str:
    """Escape a third-party value for Markdown.

    Findings are attacker-influenced text. Unescaped, a value containing ] or ( breaks out of
    the link syntax, and raw HTML passes straight through most Markdown renderers.
    """
    for char in ("\\", "`", "*", "_", "[", "]", "(", ")", "<", ">", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text.replace("\r", " ").replace("\n", " ")


def safe_url(url: str | None) -> str | None:
    """Findings come from third parties, so a url is only a link if its scheme is one we allow.

    Public and registered as a Jinja filter, because the web templates used to re-express this
    inline and got it subtly wrong: their version omitted the casefold, so HTTPS://x rendered as
    plain text in the app while linking in an export.
    """
    if url and url.lower().startswith(_SAFE_SCHEMES):
        return url
    return None


def _credit(case: Case) -> bool:
    """CC BY-SA asks for attribution where the material is used, and an exported file is the one
    artifact that leaves this machine without the vendored licence beside it."""
    return any(s.source_id == SOURCE_ID for s in case.stars)


def _by_target(case: Case):
    """Findings grouped the way the case is organised: identifier first, then source.

    A case spans several identifiers, so a flat source list would put a domain's DNS records
    next to a username's profile hits with nothing saying which was which.
    """
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
            for s in stars:
                url = safe_url(s.url)
                rendered = f"[{_md(s.value)}]({url})" if url else _md(s.value)
                # When it was captured, not just what: an undated observation is not evidence,
                # and a case routinely holds rows captured weeks apart.
                seen = f" _(saved {_md(when(s.starred_at))})_" if s.starred_at else ""
                lines.append(f"- **{_md(s.label)}**: {rendered}{seen}")
    lines += ["", "---", "", "Exported by casefile. Only starred findings are included."]
    if _credit(case):
        lines += ["", f"{_md(CREDIT)} {CREDIT_URL}"]
    return "\n".join(lines) + "\n"


def _to_json(case: Case) -> str:
    return json.dumps(
        {
            "name": case.name,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "targets": [
                {"entity_type": t.entity_type, "value": t.value, "star_count": t.star_count} for t in case.targets
            ],
            "stars": [
                {
                    "target_type": s.target_type,
                    "target_value": s.target_value,
                    "source_id": s.source_id,
                    "label": s.label,
                    "value": s.value,
                    "url": s.url,
                    "starred_at": s.starred_at,
                }
                for s in case.stars
            ],
            **({"attribution": [{"text": CREDIT, "url": CREDIT_URL}]} if _credit(case) else {}),
        },
        indent=2,
    )


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
            parts.append(f"<h3>{escape(source_id)}</h3><ul>")
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


# The one place a format is declared: renderer and media type together, so the download route
# cannot know about a format the renderer does not have, or type it differently.
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
    return render(case)
