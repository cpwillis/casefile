"""Optional API keys, from the environment or a local .env. Stdlib only, by budget."""

import os
from pathlib import Path


def get_key(name: str, env_path: Path | None = None) -> str | None:
    """Environment first, then a .env file. Empty values count as absent."""
    if value := os.environ.get(name, "").strip():
        return value
    path = env_path if env_path is not None else Path.cwd() / ".env"
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if key.strip() == name:
            return raw.strip().strip("\"'").strip() or None
    return None
