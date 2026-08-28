"""argparse entry point: print results, emit JSON, or launch the local web app."""

import argparse
import json
import sys
from dataclasses import asdict

from casefile import __version__
from casefile.report import Section, build_report

REPO = "https://github.com/cpwillis/casefile"


def _render_text(raw: str, sections: tuple[Section, ...]) -> str:
    lines = [raw]
    for index, section in enumerate(sections):
        marker = "most likely" if index == 0 else ""
        lines.append("")
        lines.append(f"  {section.type.upper():<14} {section.value:<40} {marker}")
        if not section.links:
            lines.append("    no sources")
        for link in section.links:
            lines.append(f"    {link.name:<28} {link.url}")
    return "\n".join(lines)


def _render_json(raw: str, sections: tuple[Section, ...]) -> str:
    return json.dumps({"input": raw, "candidates": [asdict(s) for s in sections]}, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casefile",
        description="One input box, every relevant OSINT pivot. Runs locally.",
        epilog=f"Exactly one target per run, by design. {REPO}",
    )
    parser.add_argument("value", nargs="?", help="the identifier to look up")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--port", type=int, default=8765, help="port for the web app (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser on launch")
    parser.add_argument("--version", action="version", version=f"casefile {__version__}")
    args = parser.parse_args(argv)

    if args.value is None:
        from casefile.web.app import serve

        return serve(port=args.port, open_browser=not args.no_browser)

    sections = build_report(args.value)
    if not sections:
        print(f"nothing recognised in {args.value!r}", file=sys.stderr)
        return 1

    render = _render_json if args.json else _render_text
    print(render(args.value, sections))
    return 0
