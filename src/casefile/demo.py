"""Build the static demo: the real app rendered against canned data, then written to disk.

The demo is a prerender of the actual templates, not a copy of them. `demo=True` is the only
difference, and it lives inside the same base.html, index.html and result.html the live app
uses, so a change to the result page cannot land in one and miss the other. It is inert by
construction: there is no backend behind it, so every dynamic affordance is either baked in or
rendered disabled rather than left dangling.
"""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from casefile.fetchers import Finding, SourceResult

# Inside the package, not at the repo root: --build-demo is advertised in --help to every
# installed user, and a repo-relative path crashes on any wheel install.
DEMO_DATA = Path(__file__).resolve().parent / "demo_data" / "demo.json"

# htmx is deliberately absent: nothing in a built page swaps, so shipping it would be 51KB of
# dead weight on the one page served to strangers.
DEMO_ASSETS = ("casefile.css", "casefile.js")


@dataclass(frozen=True)
class DemoTarget:
    query: str
    slug: str
    panels: dict[str, SourceResult]


def _slug(query: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in query]
    return "".join(keep).strip("-").replace("--", "-") or "target"


def load_targets(path: Path | None = None) -> tuple[DemoTarget, ...]:
    document = json.loads((path or DEMO_DATA).read_text())
    targets = []
    for entry in document["targets"]:
        panels = {
            source_id: SourceResult(
                source_id=source_id,
                state=spec["state"],
                findings=tuple(
                    Finding(label=f["label"], value=f["value"], url=f.get("url")) for f in spec.get("findings", [])
                ),
                detail=spec.get("detail"),
            )
            for source_id, spec in entry.get("panels", {}).items()
        }
        targets.append(DemoTarget(query=entry["query"], slug=_slug(entry["query"]), panels=panels))
    return tuple(targets)


def build_demo(out_dir: Path, data: Path | None = None) -> list[Path]:
    """Render the demo into out_dir. Returns the files written."""
    from casefile.web.app import HERE, sections_for, templates

    out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_targets(data)
    written: list[Path] = []

    nav = [{"query": t.query, "href": f"{t.slug}.html"} for t in targets]

    index = templates.get_template("index.html").render(demo=True, targets=nav)
    (out_dir / "index.html").write_text(index)
    written.append(out_dir / "index.html")

    for target in targets:
        html = templates.get_template("result.html").render(
            demo=True,
            raw=target.query,
            sections=sections_for(target.query, target.panels),
            targets=nav,
        )
        path = out_dir / f"{target.slug}.html"
        path.write_text(html)
        written.append(path)

    static_out = out_dir / "static"
    static_out.mkdir(exist_ok=True)
    for name in DEMO_ASSETS:
        shutil.copy2(HERE / "static" / name, static_out / name)
        written.append(static_out / name)
    return written


def demo_slug_for(query: str) -> str:
    return _slug(query)
