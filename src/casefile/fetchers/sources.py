"""Concrete keyless fetchers. Importing this module registers them."""

import ipaddress
from urllib.parse import quote

import httpx
import phonenumbers
from phonenumbers import PhoneNumberFormat, carrier, geocoder, timezone

from casefile.config import get_key
from casefile.fetchers import Finding, NeedsKey, fetcher, http
from casefile.types import EntityType

_DNS_TYPES = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS"}


@fetcher(id="dns", accepts=[EntityType.DOMAIN, EntityType.EMAIL])
async def dns(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    name = value.split("@")[-1] if entity_type is EntityType.EMAIL else value
    findings: list[Finding] = []
    for qtype in ("A", "AAAA", "MX", "TXT", "NS"):
        resp = await http.get(
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
    resp = await http.get(client, f"https://rdap.org/{kind}/{quote(key, safe='')}", "rdap.org")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
    for event in data.get("events", []):
        findings.append(Finding(label=event.get("eventAction", "event"), value=event.get("eventDate", "")))
    return findings


@fetcher(id="crtsh", accepts=[EntityType.DOMAIN])
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.get(client, "https://crt.sh/", "crt.sh", params={"q": value, "output": "json"})
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
    # is_global is True only for publicly routable addresses. False covers private, loopback,
    # link-local, CGNAT and the RFC 5737/3849 documentation ranges, for both v4 and v6.
    if not address.is_global:
        return []  # verified: 10.0.0.1 returns 200 with junk data, so never ask
    resp = await http.get(
        client,
        f"https://internetdb.shodan.io/{quote(value, safe='')}",
        "internetdb.shodan.io",
        allow=(404,),
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings = [Finding(label=label, value=str(item)) for key, label in _INTERNETDB_LISTS for item in data.get(key, [])]
    findings += [
        Finding(label="vuln", value=str(v), url=f"https://nvd.nist.gov/vuln/detail/{v}") for v in data.get("vulns", [])
    ]
    return findings


# (json key, label) for the plain list fields. vulns is separate: it is the only one with a url.
_INTERNETDB_LISTS = (("ports", "port"), ("hostnames", "hostname"), ("cpes", "cpe"), ("tags", "tag"))

_GITHUB_FIELDS = ("name", "company", "location", "bio", "blog", "public_repos", "created_at")


@fetcher(id="github", accepts=[EntityType.USERNAME])
async def github(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.get(
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


@fetcher(id="wikidata", accepts=[EntityType.PERSON, EntityType.COMPANY])
async def wikidata(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.get(
        client,
        "https://www.wikidata.org/w/api.php",
        "www.wikidata.org",
        params={
            "action": "wbsearchentities",
            "search": value,
            "language": "en",
            "format": "json",
            "limit": 5,
        },
    )
    findings: list[Finding] = []
    for item in resp.json().get("search", []):
        entity_id = item.get("id", "")
        findings.append(
            Finding(
                label=item.get("label", entity_id),
                value=item.get("description", "no description"),
                url=f"https://www.wikidata.org/wiki/{entity_id}" if entity_id else None,
            )
        )
    return findings


# hashlookup exposes one path per digest length. Our detector accepts 32/40/64 hex chars.
_HASHLOOKUP_PATHS = {32: "md5", 40: "sha1", 64: "sha256"}


@fetcher(id="hashlookup", accepts=[EntityType.HASH])
async def hashlookup(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """CIRCL hashlookup: known-GOOD (NSRL) data, so a hit means a recognised legitimate file."""
    kind = _HASHLOOKUP_PATHS.get(len(value))
    if kind is None:
        return []
    resp = await http.get(
        client,
        f"https://hashlookup.circl.lu/lookup/{kind}/{quote(value, safe='')}",
        "hashlookup.circl.lu",
        allow=(404,),
        headers={"accept": "application/json"},
    )
    if resp.status_code == 404:
        return []
    data = resp.json()
    findings: list[Finding] = []
    if name := data.get("FileName"):
        findings.append(Finding(label="known file", value=str(name)))
    if size := data.get("FileSize"):
        findings.append(Finding(label="size", value=f"{size} bytes"))
    if product := (data.get("ProductCode") or {}).get("ProductName"):
        findings.append(Finding(label="product", value=str(product)))
    return findings


_BAZAAR_FIELDS = (
    ("file_name", "file"),
    ("signature", "signature"),
    ("file_type", "type"),
    ("first_seen", "first seen"),
)


@fetcher(id="malwarebazaar", accepts=[EntityType.HASH])
async def malwarebazaar(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """abuse.ch requires an Auth-Key as of 2024, so this is a needs_key source by necessity."""
    key = get_key("ABUSECH_AUTH_KEY")
    if not key:
        raise NeedsKey("set ABUSECH_AUTH_KEY in .env to enable MalwareBazaar")
    resp = await http.post(
        client,
        "https://mb-api.abuse.ch/api/v1/",
        "mb-api.abuse.ch",
        data={"query": "get_info", "hash": value},
        headers={"Auth-Key": key},
    )
    payload = resp.json()
    if payload.get("error") == "Unauthorized" or payload.get("query_status") == "unauthorized":
        raise NeedsKey("ABUSECH_AUTH_KEY was rejected by abuse.ch")
    if payload.get("query_status") != "ok":
        return []  # hash_not_found and friends mean looked-and-found-nothing
    findings: list[Finding] = []
    for row in payload.get("data", []):
        findings += [Finding(label=label, value=str(v)) for key, label in _BAZAAR_FIELDS if (v := row.get(key))]
        findings += [Finding(label="tag", value=str(t)) for t in row.get("tags") or []]
    return findings


_PHONE_TYPES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
    phonenumbers.PhoneNumberType.VOIP: "voip",
}


@fetcher(id="phone_meta", accepts=[EntityType.PHONE])
async def phone_meta(value: str, entity_type: EntityType, client) -> list[Finding]:
    """Offline. libphonenumber metadata only; makes no network request at all."""
    try:
        parsed = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        # The _phone detector only yields digit strings, so a parse failure with no leading
        # "+" is always the missing-country-code case, whatever libphonenumber calls it.
        if not value.strip().startswith("+"):
            return [
                Finding(
                    label="note",
                    value="no country code: prefix with + and the country code for region, carrier and timezone",
                )
            ]
        return []
    findings = [Finding(label="valid", value="yes" if phonenumbers.is_valid_number(parsed) else "no")]
    if region := phonenumbers.region_code_for_number(parsed):
        findings.append(Finding(label="region", value=region))
    if location := geocoder.description_for_number(parsed, "en"):
        findings.append(Finding(label="location", value=location))
    if name := carrier.name_for_number(parsed, "en"):  # empty for most landlines
        findings.append(Finding(label="carrier", value=name))
    for zone in timezone.time_zones_for_number(parsed):
        findings.append(Finding(label="timezone", value=zone))
    if label := _PHONE_TYPES.get(phonenumbers.number_type(parsed)):
        findings.append(Finding(label="line type", value=label))
    findings.append(Finding(label="E.164", value=phonenumbers.format_number(parsed, PhoneNumberFormat.E164)))
    findings.append(
        Finding(label="international", value=phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL))
    )
    return findings


from casefile.fetchers import wmn  # noqa: E402,F401 -- registers the whatsmyname fetcher
