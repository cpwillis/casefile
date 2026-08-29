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

FORMATS = ("md", "json", "html")

_SAFE_SCHEMES = ("https://", "http://")

_HTML_CSS = """
:root { color-scheme: light dark; }
body { font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; max-width: 46rem; margin: 3rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; margin-bottom: .2rem; }
h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .05em; margin-top: 2rem; }
.meta { color: #6b6b6b; font-size: .85rem; margin-top: 0; }
ul { list-style: none; padding: 0; }
li { display: flex; gap: .75rem; padding: .2rem 0; border-bottom: 1px solid rgba(128,128,128,.2); }
.label { color: #6b6b6b; min-width: 8rem; }
"""


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _safe_url(url: str | None) -> str | None:
    """Findings come from third parties, so a url is only a link if its scheme is one we allow."""
    if url and url.lower().startswith(_SAFE_SCHEMES):
        return url
    return None


def _by_source(case: Case):
    ordered = sorted(case.stars, key=lambda s: (s.source_id, s.label, s.value))
    return groupby(ordered, key=lambda s: s.source_id)


def _to_markdown(case: Case) -> str:
    lines = [
        f"# {case.value}",
        "",
        f"`{case.entity_type}` · {case.star_count} saved · last updated {_when(case.updated_at)}",
    ]
    for source_id, stars in _by_source(case):
        lines += ["", f"## {source_id}", ""]
        for s in stars:
            url = _safe_url(s.url)
            rendered = f"[{s.value}]({url})" if url else s.value
            lines.append(f"- **{s.label}**: {rendered}")
    lines += ["", "---", "", "Exported by casefile. Only starred findings are included."]
    return "\n".join(lines) + "\n"


def _to_json(case: Case) -> str:
    return json.dumps(
        {
            "target": case.value,
            "entity_type": case.entity_type,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "stars": [{"source_id": s.source_id, "label": s.label, "value": s.value, "url": s.url} for s in case.stars],
        },
        indent=2,
    )


def _to_html(case: Case) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{escape(case.value)} — casefile</title>",
        f"<style>{_HTML_CSS}</style>",
        "</head><body>",
        f"<h1>{escape(case.value)}</h1>",
        f'<p class="meta">{escape(case.entity_type)} · {case.star_count} saved · '
        f"last updated {_when(case.updated_at)}</p>",
    ]
    for source_id, stars in _by_source(case):
        parts.append(f"<h2>{escape(source_id)}</h2><ul>")
        for s in stars:
            url = _safe_url(s.url)
            value = (
                f'<a href="{escape(url)}" rel="noreferrer noopener">{escape(s.value)}</a>' if url else escape(s.value)
            )
            parts.append(f'<li><span class="label">{escape(s.label)}</span><span>{value}</span></li>')
        parts.append("</ul>")
    parts.append('<p class="meta">Exported by casefile. Only starred findings are included.</p>')
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


_RENDERERS = {"md": _to_markdown, "json": _to_json, "html": _to_html}


def export_case(case: Case, fmt: str) -> str:
    try:
        render = _RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"unknown export format {fmt!r}, expected one of {', '.join(FORMATS)}") from None
    return render(case)
