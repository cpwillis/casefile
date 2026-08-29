"""Build the static demo: the real app rendered against canned data, then written to disk.

The demo is a prerender of the actual templates, not a mockup, so it cannot drift from what
casefile does. It is inert by construction: there is no backend behind it, so every dynamic
affordance is either baked in or rendered disabled rather than left dangling.
"""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from casefile.detect import detect
from casefile.fetchers import Finding, SourceResult, fetchers_for
from casefile.report import links_for

# Inside the package, not at the repo root: --build-demo is advertised in --help to every
# installed user, and a repo-relative path crashes on any wheel install.
DEMO_DATA = Path(__file__).resolve().parent / "demo_data" / "demo.json"


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


def _sections_for(target: DemoTarget) -> list[dict]:
    """The same shape the live result route builds, with panels resolved rather than deferred."""
    sections = []
    for candidate in detect(target.query):
        prerendered, unavailable = [], []
        for source_id in fetchers_for(candidate.type):
            if source_id in target.panels:
                prerendered.append(target.panels[source_id])
            else:
                unavailable.append(source_id)
        sections.append(
            {
                "type": candidate.type.value,
                "value": candidate.value,
                "prerendered": prerendered,
                "unavailable": unavailable,
                "links": list(links_for(candidate)),
            }
        )
    return sections


def build_demo(out_dir: Path, data: Path | None = None) -> list[Path]:
    """Render the demo into out_dir. Returns the files written."""
    from casefile.web.app import HERE, templates

    out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_targets(data)
    written: list[Path] = []

    nav = [{"query": t.query, "href": f"{t.slug}.html"} for t in targets]

    index = templates.get_template("demo_index.html").render(demo=True, targets=nav)
    (out_dir / "index.html").write_text(index)
    written.append(out_dir / "index.html")

    for target in targets:
        html = templates.get_template("demo_result.html").render(
            demo=True,
            raw=target.query,
            sections=_sections_for(target),
            targets=nav,
        )
        path = out_dir / f"{target.slug}.html"
        path.write_text(html)
        written.append(path)

    static_out = out_dir / "static"
    if static_out.exists():
        shutil.rmtree(static_out)
    shutil.copytree(HERE / "static", static_out)
    written.extend(sorted(static_out.iterdir()))
    return written


def demo_slug_for(query: str) -> str:
    return _slug(query)
