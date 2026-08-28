"""Concrete keyless fetchers. Importing this module registers them."""

import ipaddress
from urllib.parse import quote

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
        resp = await get_json(
            client,
            "https://cloudflare-dns.com/dns-query",
            "cloudflare-dns.com",
            params={"name": name, "type": qtype},
            headers={"accept": "application/dns-json"},
        )
        for row in resp.json().get("Answer", []):
            label = _DNS_TYPES.get(row.get("type"), str(row.get("type")))
            findings.append(Finding(label=label, value=row.get("data", "")))
    return findings


@fetcher(id="rdap", accepts=[EntityType.DOMAIN, EntityType.IP, EntityType.ASN])
async def rdap(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    kind = {EntityType.DOMAIN: "domain", EntityType.IP: "ip", EntityType.ASN: "autnum"}[entity_type]
    key = value[2:] if entity_type is EntityType.ASN else value  # rdap wants a bare AS number
    resp = await get_json(client, f"https://rdap.org/{kind}/{quote(key, safe='')}", "rdap.org")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
    for event in data.get("events", []):
        findings.append(Finding(label=event.get("eventAction", "event"), value=event.get("eventDate", "")))
    return findings


@fetcher(id="crtsh", accepts=[EntityType.DOMAIN])
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(client, "https://crt.sh/", "crt.sh", params={"q": value, "output": "json"})
    names: set[str] = set()
    for row in resp.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)
    return [Finding(label="subdomain", value=n, url=f"https://{n}") for n in sorted(names)]


@fetcher(id="internetdb", accepts=[EntityType.IP])
async def internetdb(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Keyless Shodan InternetDB. A 200 always carries the full object; 404 is the only miss."""
    address = ipaddress.ip_address(value)
    # Skip RFC 1918 private ranges, loopback, and link-local (not is_private which includes TEST-NET)
    if address.is_loopback or address.is_link_local:
        return []
    if (
        address in ipaddress.ip_network("10.0.0.0/8")
        or address in ipaddress.ip_network("172.16.0.0/12")
        or address in ipaddress.ip_network("192.168.0.0/16")
    ):
        return []  # verified: 10.0.0.1 returns 200 with junk data, so never ask
    resp = await get_json(
        client,
        f"https://internetdb.shodan.io/{quote(value, safe='')}",
        "internetdb.shodan.io",
        allow=(404,),
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings: list[Finding] = []
    for port in data.get("ports", []):
        findings.append(Finding(label="port", value=str(port)))
    for host in data.get("hostnames", []):
        findings.append(Finding(label="hostname", value=host))
    for cpe in data.get("cpes", []):
        findings.append(Finding(label="cpe", value=cpe))
    for tag in data.get("tags", []):
        findings.append(Finding(label="tag", value=tag))
    for vuln in data.get("vulns", []):
        findings.append(Finding(label="vuln", value=vuln, url=f"https://nvd.nist.gov/vuln/detail/{vuln}"))
    return findings


_GITHUB_FIELDS = ("name", "company", "location", "bio", "blog", "public_repos", "created_at")


@fetcher(id="github", accepts=[EntityType.USERNAME])
async def github(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await get_json(
        client,
        f"https://api.github.com/users/{quote(value, safe='')}",
        "api.github.com",
        allow=(404,),
        headers={"accept": "application/vnd.github+json"},
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings = [
        Finding(label=field, value=str(data[field])) for field in _GITHUB_FIELDS if data.get(field) not in (None, "", 0)
    ]
    if url := data.get("html_url"):
        findings.append(Finding(label="profile", value=data.get("login", value), url=url))
    return findings
