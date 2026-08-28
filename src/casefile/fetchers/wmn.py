"""WhatsMyName: 716 vendored site definitions and the username checker over them.

Data is CC BY-SA 4.0 and vendored unmodified. See src/casefile/vendor/WMN-LICENCE.txt.
"""

import asyncio
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

import httpx

from casefile.fetchers import Finding, fetcher
from casefile.fetchers.http import domain_slot
from casefile.types import EntityType

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


# ponytail: one panel for all 716 sites, so it returns in 30-60s rather than streaming.
# Chunk into ~10 panels of 70 sites if that latency actually annoys anyone.


def account_exists(site: Site, status: int, body: str) -> bool:
    """The false-positive mitigation. Status alone is never enough when a marker exists."""
    if status != site.e_code:
        return False
    if site.e_string:
        return site.e_string in body
    if site.m_string and site.m_string in body:  # noqa: SIM103 -- explicit branch reads clearer than a negation
        return False  # the missing-marker is present, so the account is absent
    return True


async def _check_one(site: Site, username: str, client: httpx.AsyncClient) -> Finding | None:
    try:
        url = check_url(site, username)
        host = httpx.URL(url).host
        async with domain_slot(host):
            resp = await client.get(url)
    except Exception:  # noqa: BLE001 -- one dead or malformed site must not sink the other 715
        return None
    if not account_exists(site, resp.status_code, resp.text):
        return None
    note = f"({', '.join(site.protection)})" if site.protection else None
    return Finding(label=site.name, value=note or site.cat, url=url)


@fetcher(id="whatsmyname", accepts=[EntityType.USERNAME])
async def whatsmyname(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    sites = load_sites()
    results = await asyncio.gather(*(_check_one(s, value, client) for s in sites))
    return sorted((f for f in results if f is not None), key=lambda f: f.label.lower())
