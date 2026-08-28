"""Concrete keyless fetchers. Importing this module registers them."""

import httpx

from casefile.fetchers import Finding, fetcher
from casefile.fetchers.http import get_json
from casefile.types import EntityType

_DNS_TYPES = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS"}


@fetcher(id="dns", accepts=[EntityType.DOMAIN, EntityType.EMAIL])
async def dns(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    name = value.split("@")[-1] if entity_type is EntityType.EMAIL else value
    findings: list[Finding] = []
    for qtype in ("A", "AAAA", "MX", "TXT", "NS"):
        url = f"https://cloudflare-dns.com/dns-query?name={name}&type={qtype}"
        resp = await get_json(client, url, "cloudflare-dns.com", headers={"accept": "application/dns-json"})
        for row in resp.json().get("Answer", []):
            label = _DNS_TYPES.get(row.get("type"), str(row.get("type")))
            findings.append(Finding(label=label, value=row.get("data", "")))
    return findings


@fetcher(id="rdap", accepts=[EntityType.DOMAIN, EntityType.IP, EntityType.ASN])
async def rdap(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    kind = {EntityType.DOMAIN: "domain", EntityType.IP: "ip", EntityType.ASN: "autnum"}[entity_type]
    key = value[2:] if entity_type is EntityType.ASN else value  # rdap wants a bare AS number
    resp = await get_json(client, f"https://rdap.org/{kind}/{key}", "rdap.org")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
    for event in data.get("events", []):
        findings.append(Finding(label=event.get("eventAction", "event"), value=event.get("eventDate", "")))
    return findings


@fetcher(id="crtsh", accepts=[EntityType.DOMAIN])
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(client, f"https://crt.sh/?q={value}&output=json", "crt.sh")
    names: set[str] = set()
    for row in resp.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)
    return [Finding(label="subdomain", value=n, url=f"https://{n}") for n in sorted(names)]
