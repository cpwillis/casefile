"""Build the static demo: the real templates rendered against canned data, with `demo=True` the only difference."""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from casefile.fetchers import Finding, SourceResult

# Inside the package, not the repo root: --build-demo is in --help for every install, and a repo path breaks a wheel.
DEMO_DATA = Path(__file__).resolve().parent / "demo_data" / "demo.json"

# htmx deliberately absent: nothing in a built page swaps, so it would be 51KB of dead weight.
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

    # Replaced, not merged: merging left the 51KB htmx of an earlier build in a demo that no longer loads it.
    static_out = out_dir / "static"
    shutil.rmtree(static_out, ignore_errors=True)
    static_out.mkdir(parents=True)
    for name in DEMO_ASSETS:
        shutil.copy2(HERE / "static" / name, static_out / name)
        written.append(static_out / name)
    return written
