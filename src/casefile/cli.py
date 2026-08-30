"""argparse entry point: print results, emit JSON, or launch the local web app."""

import argparse
import asyncio
import contextlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

import casefile.fetchers.sources  # noqa: F401 -- registers fetchers
from casefile import __version__
from casefile.cache import clear_cache, run_cached
from casefile.cases import forget_all, list_cases, load_case
from casefile.catalog import links_for
from casefile.detect import detect
from casefile.export import FORMATS, export_case, sanitize
from casefile.fetchers import fetched_ids, fetchers_for
from casefile.fetchers.http import build_client
from casefile.linkcheck import check_links, tally

REPO = "https://github.com/cpwillis/casefile"


def _wanted(record, deep) -> bool:
    """Whether an on-demand source runs. `deep` is True for all, or a list of ids: the browser asks per panel."""
    if not record.on_demand:
        return True
    return deep is True or record.id in (deep or ())


async def _fetch_all(candidates, use_cache: bool = True, deep=False):
    async with build_client() as client:
        results = {}
        for c in candidates:
            due = [r for r in fetchers_for(c.type) if _wanted(r, deep)]
            got = await asyncio.gather(*(run_cached(r.id, c.value, c.type, client, use_cache=use_cache) for r in due))
            results[(c.type, c.value)] = got
        return results


def _shown_links(candidate, results):
    """Links for a candidate, minus the sources printed above them. Keyed on what ran, not on what has a fetcher."""
    fetched = {r.source_id for r in results.get((candidate.type, candidate.value), [])}
    return links_for(candidate, exclude=frozenset(fetched))


async def _check_all(candidates, results):
    """One verdict per link, for every reading. Opt-in like the web button: a request per link, sent from your IP."""
    async with build_client() as client:
        out = {}
        for c in candidates:  # exactly the links that are shown, so no request goes out for a link never printed
            out[(c.type, c.value)] = await check_links(_shown_links(c, results), client)
        return out


def _render_links(candidates, results, verdicts):
    lines = []
    for c in candidates:
        marks = verdicts.get((c.type, c.value), {})
        lines.append(f"\n  {c.type.value.upper():<14} {c.value}")
        for link in _shown_links(c, results):
            verdict = marks.get(link.id, "")
            lines.append(f"    {verdict:<12} {link.name:<28} {link.url}")
        counts = tally(marks)
        lines.append("    " + " · ".join(f"{n} {name}" for name, n in sorted(counts.items())))
    lines.append("\n  only 404 and 410 count as missing; blocked, redirected and unreachable tell you nothing")
    return "\n".join(lines)


def _render_text(raw, candidates, results):
    lines = [raw]
    for i, c in enumerate(candidates):
        lines.append("")
        lines.append(f"  {c.type.value.upper():<14} {c.value:<40} {'most likely' if i == 0 else ''}")
        for r in results.get((c.type, c.value), []):
            detail = f": {sanitize(r.detail)}" if r.detail else ""
            lines.append(f"    [{r.state}] {r.source_id}{detail}")
            for f in r.findings:
                # the url is often the whole result (a WhatsMyName hit's value is a category), so text mode must keep it
                url = f"  {sanitize(f.url)}" if f.url else ""
                lines.append(f"      {sanitize(f.label)}: {sanitize(f.value)}{url}")
        # notes go to --json, the web and exports, not here: 46 of 49 domain sources have one and they run long
        for link in _shown_links(c, results):
            lines.append(f"    {link.name:<28} {link.url}")
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
                    "links": [asdict(link) for link in _shown_links(c, results)],
                }
                for c in candidates
            ],
        },
        indent=2,
    )


def _port(text: str) -> int:
    n = int(text)  # a non-int raises ValueError, which argparse turns into a clean usage error
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"port must be between 1 and 65535, not {n}")
    return n


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # third-party text is UTF-8; a latin-1 terminal would otherwise traceback mid-print. A captured or
        # detached stream (tests, a pipe closed early) has no reconfigure, hence the suppress.
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="casefile",
        description="One input box, every relevant OSINT pivot. Runs locally.",
        epilog=f"With no identifier, casefile launches the local web app (see --port, --no-browser). {REPO}",
    )
    parser.add_argument("value", nargs="?", help="the identifier to look up; omit it to launch the local web app")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--no-fetch", action="store_true", help="skip live fetching, show links only")
    parser.add_argument("--no-cache", action="store_true", help="bypass the response cache")
    parser.add_argument(
        "--deep",
        nargs="?",
        const="",
        metavar="SOURCES",
        help="also run on-demand sources: bare for all, or a comma-separated list of ids. These are the "
        "sources whose egress is large enough to need consent, so they are off by default.",
    )
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="probe each catalogue link and flag the ones that are definitely gone",
    )
    parser.add_argument("--clear-cache", action="store_true", help="purge the response cache and exit")
    parser.add_argument("--cases", action="store_true", help="list your saved cases and exit")
    parser.add_argument("--build-demo", metavar="DIR", help="render the static demo into DIR and exit")
    parser.add_argument("--export", metavar="CASE_ID", help="export one saved case and exit")
    parser.add_argument(
        "--format", default="md", choices=FORMATS, help=f"export format: {', '.join(FORMATS)} (default: md)"
    )
    parser.add_argument(
        "--forget-cases",
        action="store_true",
        help="delete every saved case and exit. Separate from --clear-cache on purpose: a privacy "
        "purge must never destroy the work you deliberately saved.",
    )
    parser.add_argument("--port", type=_port, default=8765, help="port for the web app (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser on launch")
    parser.add_argument("--version", action="version", version=f"casefile {__version__}")
    args = parser.parse_args(argv)

    # `--deep <target>` makes argparse hand the target to --deep, leaving no identifier and silently launching the
    # web app. If what it grabbed is not a known source id and no identifier was given, it was the identifier: all.
    if args.value is None and args.deep and args.deep not in fetched_ids():
        args.value, args.deep = args.deep, ""

    if args.build_demo:
        from casefile.demo import build_demo

        written = build_demo(Path(args.build_demo))
        print(f"wrote {len(written)} files to {args.build_demo}")
        return 0

    if args.clear_cache:
        print(f"cleared {clear_cache()} cached responses")
        return 0

    if args.forget_cases:
        print(f"forgot {forget_all()} saved cases")
        return 0

    if args.cases:
        saved = list_cases()
        if not saved:
            print("no saved cases yet: save an identifier in the browser, or star a finding", file=sys.stderr)
            return 1
        for c in saved:
            targets = ", ".join(t.value for t in c.targets)
            print(f"{c.id}  {c.name[:28]:28} {c.star_count:>3} saved  {targets}")
        return 0

    if args.export:
        case = load_case(args.export)
        if case is None:
            print(f"no such case {args.export!r}", file=sys.stderr)
            return 1
        # third-party text on a terminal, same as the text renderer; \n and \t survive because an export is multi-line
        print(export_case(case, args.format))
        return 0

    if args.value is None:
        # the one import worth deferring: starlette and uvicorn cost ~64ms that `casefile <target>` should not pay
        from casefile.web.app import serve

        return serve(port=args.port, open_browser=not args.no_browser)

    candidates = detect(args.value)
    if not candidates:
        print(f"nothing recognised in {args.value!r}", file=sys.stderr)
        return 1

    deep = True if args.deep == "" else (args.deep.split(",") if args.deep else False)
    results = {} if args.no_fetch else asyncio.run(_fetch_all(candidates, use_cache=not args.no_cache, deep=deep))
    if args.check_links:
        verdicts = asyncio.run(_check_all(candidates, results))
        print(_render_links(candidates, results, verdicts))
        return 0
    render = _render_json if args.json else _render_text
    print(render(args.value, candidates, results))
    return 0
