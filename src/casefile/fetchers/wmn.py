"""WhatsMyName: 716 vendored site definitions and the username checker over them.

Data is CC BY-SA 4.0 and vendored unmodified. See src/casefile/vendor/WMN-LICENCE.txt.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

DATA_PATH = Path(__file__).resolve().parents[1] / "vendor" / "wmn-data.json"
WMN_ATTRIBUTION = (
    "Username checks use the WhatsMyName dataset by Micah Hoffman and contributors, "
    "licensed CC BY-SA 4.0: https://github.com/WebBreacher/WhatsMyName"
)
PLACEHOLDER = "{account}"


@dataclass(frozen=True, slots=True)
class Site:
    name: str
    uri_check: str
    e_code: int
    e_string: str
    m_code: int
    m_string: str
    cat: str
    protection: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def load_sites() -> tuple[Site, ...]:
    document = json.loads(DATA_PATH.read_text())
    return tuple(
        Site(
            name=raw["name"],
            uri_check=raw["uri_check"],
            e_code=int(raw.get("e_code", 200)),
            e_string=raw.get("e_string", "") or "",
            m_code=int(raw.get("m_code", 404)),
            m_string=raw.get("m_string", "") or "",
            cat=raw.get("cat", "other"),
            protection=tuple(raw.get("protection", ()) or ()),
        )
        for raw in document.get("sites", [])
        if PLACEHOLDER in raw.get("uri_check", "")
    )


def check_url(site: Site, username: str) -> str:
    return site.uri_check.replace(PLACEHOLDER, quote(username, safe=""))
