"""WhatsMyName: 687 usable vendored site definitions and the username checker over them.

687 is a subset of the 716 entries in the upstream file: entries without a URL-embedded
username placeholder, and entries that are not https://, are both skipped on load.

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
PLACEHOLDER = "{account}"
SOURCE_ID = "whatsmyname"
CREDIT = "Username checks use the WhatsMyName dataset by Micah Hoffman and contributors, CC BY-SA 4.0."
CREDIT_URL = "https://github.com/WebBreacher/WhatsMyName"


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
        # catalog.py hard-fails any first-party link that isn't https://; the vendored
        # dataset must not be a loophole around that, so plaintext-HTTP sites are skipped too.
        if PLACEHOLDER in raw.get("uri_check", "") and raw.get("uri_check", "").startswith("https://")
    )


def check_url(site: Site, username: str) -> str:
    return site.uri_check.replace(PLACEHOLDER, quote(username, safe=""))


# ponytail: one panel for all 687 sites, so it returns in 30-60s rather than streaming.
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


_UNREACHABLE = object()  # this site could not be reached at all, as distinct from "no account"


async def _check_one(site: Site, username: str, client: httpx.AsyncClient) -> Finding | None | object:
    try:
        url = check_url(site, username)
        host = httpx.URL(url).host
        async with domain_slot(host):
            resp = await client.get(url, follow_redirects=False)
    except Exception:  # noqa: BLE001 -- one dead or malformed site must not sink the rest
        return _UNREACHABLE
    if not account_exists(site, resp.status_code, resp.text):
        return None
    note = f"({', '.join(site.protection)})" if site.protection else None
    return Finding(label=site.name, value=note or site.cat, url=url)


@fetcher(
    id="whatsmyname",
    accepts=[EntityType.USERNAME],
    on_demand=True,
    cost_note="queries several hundred sites from your IP and takes 30 to 60 seconds",
)
async def whatsmyname(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    sites = load_sites()
    results = await asyncio.gather(*(_check_one(s, value, client) for s in sites))
    unreachable = sum(1 for r in results if r is _UNREACHABLE)
    if sites and unreachable == len(sites):
        # Raising maps to state error, which is deliberately not cacheable. Returning an empty
        # list here would cache a confident false negative about a person for a whole day.
        raise RuntimeError(f"all {unreachable} site checks failed, so nothing was actually checked")
    findings = sorted((r for r in results if isinstance(r, Finding)), key=lambda f: f.label.lower())
    if unreachable:
        findings.insert(0, Finding(label="note", value=f"{unreachable} of {len(sites)} sites could not be reached"))
    return findings
