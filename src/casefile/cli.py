"""Placeholder entry point. Replaced by the real typer CLI in phase 5."""

import argparse

from casefile import __version__

REPO = "https://github.com/cpwillis/casefile"


def main() -> int:
    parser = argparse.ArgumentParser(prog="casefile", description=__doc__)
    parser.add_argument("--version", action="version", version=f"casefile {__version__}")
    parser.parse_args()
    print(f"casefile {__version__} is a placeholder release. Nothing is implemented yet.")
    print(f"Follow development at {REPO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
