"""argparse entry point: print results, emit JSON, or launch the local web app."""

import argparse
import asyncio
import json
import sys
from dataclasses import asdict

import casefile.fetchers.sources  # noqa: F401 -- registers fetchers
from casefile import __version__
from casefile.detect import detect
from casefile.fetchers import fetchers_for, run_fetcher
from casefile.fetchers.http import build_client
from casefile.report import links_for

REPO = "https://github.com/cpwillis/casefile"


async def _fetch_all(candidates):
    async with build_client() as client:
        results = {}
        for c in candidates:
            ids = fetchers_for(c.type)
            got = await asyncio.gather(*(run_fetcher(sid, c.value, c.type, client) for sid in ids))
            results[(c.type, c.value)] = got
        return results


def _links(candidate):
    return [{"id": link.id, "name": link.name, "url": link.url} for link in links_for(candidate)]


def _render_text(raw, candidates, results):
    lines = [raw]
    for i, c in enumerate(candidates):
        lines.append("")
        lines.append(f"  {c.type.value.upper():<14} {c.value:<40} {'most likely' if i == 0 else ''}")
        for r in results.get((c.type, c.value), []):
            detail = f" {r.detail}" if r.detail else ""
            lines.append(f"    [{r.state}]{detail} {r.source_id}")
            for f in r.findings:
                lines.append(f"      {f.label}: {f.value}")
        for link in _links(c):
            lines.append(f"    {link['name']:<28} {link['url']}")
    return "\n".join(lines)


def _render_json(raw, candidates, results):
    return json.dumps(
        {
            "input": raw,
            "candidates": [
                {
                    "type": c.type.value,
                    "value": c.value,
                    "sources": [asdict(r) for r in results.get((c.type, c.value), [])],
                    "links": _links(c),
                }
                for c in candidates
            ],
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casefile",
        description="One input box, every relevant OSINT pivot. Runs locally.",
        epilog=f"Exactly one target per run, by design. {REPO}",
    )
    parser.add_argument("value", nargs="?", help="the identifier to look up")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--no-fetch", action="store_true", help="skip live fetching, show links only")
    parser.add_argument("--port", type=int, default=8765, help="port for the web app (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser on launch")
    parser.add_argument("--version", action="version", version=f"casefile {__version__}")
    args = parser.parse_args(argv)

    if args.value is None:
        from casefile.web.app import serve

        return serve(port=args.port, open_browser=not args.no_browser)

    candidates = detect(args.value)
    if not candidates:
        print(f"nothing recognised in {args.value!r}", file=sys.stderr)
        return 1

    results = {} if args.no_fetch else asyncio.run(_fetch_all(candidates))
    render = _render_json if args.json else _render_text
    print(render(args.value, candidates, results))
    return 0
