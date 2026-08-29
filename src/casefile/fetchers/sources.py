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
# DNS response codes. 0 is an answer and 3 is an authoritative "no such name", which is itself a
# finding. Everything else means the resolver could not tell us, which is not the same as "no
# records" and must never render as one.
_DNS_RCODES = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH"}


@fetcher(
    id="dns",
    accepts=[EntityType.DOMAIN, EntityType.EMAIL],
    name="DNS (Cloudflare)",
    note="Live DNS as Cloudflare's resolver sees it now, not historical records.",
)
async def dns(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    name = value.split("@")[-1] if entity_type is EntityType.EMAIL else value
    findings: list[Finding] = []
    types = ("A", "AAAA", "MX", "TXT", "NS")
    absent = 0
    for qtype in types:
        resp = await http.get(
            client,
            "https://cloudflare-dns.com/dns-query",
            "cloudflare-dns.com",
            params={"name": name, "type": qtype},
            headers={"accept": "application/dns-json"},
        )
        data = resp.json()
        status = data.get("Status", 0)
        if status == 3:  # NXDOMAIN: the name does not exist, which is an answer worth reporting
            absent += 1
        elif status != 0:
            # DoH answers 200 for SERVFAIL, so without this a broken zone renders as "no records"
            raise RuntimeError(f"{qtype}: resolver returned {_DNS_RCODES.get(status, status)}")
        for row in data.get("Answer", []):
            label = _DNS_TYPES.get(row.get("type"), str(row.get("type")))
            findings.append(Finding(label=label, value=row.get("data", "")))
    if absent == len(types):
        return [Finding(label="note", value="NXDOMAIN: this name does not exist in DNS", note=True)]
    return findings


def _vcard_name(entity: dict) -> str | None:
    """The display name out of an RDAP entity's jCard, which is a nested array, not an object.

    Shape is ["vcard", [["fn", {}, "text", "Some Org"], ...]], so the name has to be dug out
    positionally rather than by key.
    """
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for row in vcard[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == "fn" and isinstance(row[3], str):
            return row[3]
    return None


@fetcher(
    id="rdap",
    accepts=[EntityType.DOMAIN, EntityType.IP, EntityType.ASN],
    name="RDAP registration",
    note="Registry data. Most registrars redact registrant contact details, so absence here is not evidence.",
)
async def rdap(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    kind = {EntityType.DOMAIN: "domain", EntityType.IP: "ip", EntityType.ASN: "autnum"}[entity_type]
    key = value[2:] if entity_type is EntityType.ASN else value  # rdap wants a bare AS number
    resp = await http.get(client, f"https://rdap.org/{kind}/{quote(key, safe='')}", "rdap.org")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
    # The parts that make rdap worth querying at all: who holds it, what range it sits in, and
    # where it is delegated. Previously all three were parsed out and dropped.
    if name := data.get("name"):
        findings.append(Finding(label="name", value=str(name)))
    if country := data.get("country"):
        findings.append(Finding(label="country", value=str(country)))
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        findings.append(Finding(label="range", value=f"{start} - {end}"))
    if (start_as := data.get("startAutnum")) is not None:
        end_as = data.get("endAutnum", start_as)
        findings.append(
            Finding(label="as range", value=f"AS{start_as}" + (f" - AS{end_as}" if end_as != start_as else ""))
        )
    for entity in data.get("entities", []):
        if not isinstance(entity, dict):
            continue
        if who := _vcard_name(entity):
            for role in entity.get("roles") or ["entity"]:
                findings.append(Finding(label=str(role), value=who))
    for ns in data.get("nameservers", []):
        if isinstance(ns, dict) and (host := ns.get("ldhName")):
            findings.append(Finding(label="nameserver", value=str(host).lower()))
    for event in data.get("events", []):
        findings.append(Finding(label=event.get("eventAction", "event"), value=event.get("eventDate", "")))
    return findings


# A wildcard-heavy domain returns tens of thousands of names. Unbounded, that became one
# multi-megabyte cache row and a panel with a star button and a store read on every line.
_CRTSH_LIMIT = 500


@fetcher(
    id="crtsh",
    accepts=[EntityType.DOMAIN],
    name="crt.sh certificates",
    note="Names seen in public certificate transparency logs. A name here need not still resolve.",
)
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.get(client, "https://crt.sh/", "crt.sh", params={"q": value, "output": "json"})
    names: set[str] = set()
    for row in resp.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)
    shown = sorted(names)[:_CRTSH_LIMIT]
    findings = [Finding(label="subdomain", value=n, url=f"https://{n}") for n in shown]
    if len(names) > len(shown):
        # Said out loud, never a silent slice: "247 subdomains" that quietly became 500 is the
        # same confident-wrong-answer class as an unqueried source rendering as empty.
        note = f"{len(names)} names found, showing the first {len(shown)} in order"
        findings.insert(0, Finding(label="note", value=note, note=True))
    return findings


@fetcher(
    id="internetdb",
    accepts=[EntityType.IP],
    name="Shodan InternetDB",
    note="Shodan's last scan of this address, which may be days old and is not a live port check.",
)
async def internetdb(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Keyless Shodan InternetDB. A 200 always carries the full object; 404 is the only miss."""
    address = ipaddress.ip_address(value)
    # is_global is True only for publicly routable addresses. False covers private, loopback,
    # link-local, CGNAT and the RFC 5737/3849 documentation ranges, for both v4 and v6.
    if not address.is_global:
        # Skipped, not empty. Verified: 10.0.0.1 answers 200 with junk, so asking is worse than
        # useless, but rendering that as "responded, nothing found" claims an answer we never got.
        return [Finding(label="note", value="not a public address, so InternetDB was not queried", note=True)]
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


@fetcher(
    id="github",
    accepts=[EntityType.USERNAME],
    name="GitHub profile",
)
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


@fetcher(
    id="wikidata",
    accepts=[EntityType.PERSON, EntityType.COMPANY],
    name="Wikidata name search",
    note="A full-text search for the name. Matches are not filtered by whether they are people or organisations.",
)
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


@fetcher(
    id="hashlookup",
    accepts=[EntityType.HASH],
    name="CIRCL hashlookup",
    note="A known-GOOD corpus (NSRL). A hit means the file is a recognised legitimate one, not a malicious one.",
)
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
        findings.append(Finding(label="known good file", value=str(name)))
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


@fetcher(
    id="malwarebazaar",
    accepts=[EntityType.HASH],
    name="MalwareBazaar",
    note="A known-BAD corpus. A hit means the sample was submitted as malware.",
)
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


@fetcher(
    id="phone_meta",
    accepts=[EntityType.PHONE],
    name="Phone number metadata",
    note="Offline metadata from libphonenumber. It says the number is well formed for its region, "
    "not that it is allocated or in service, and the carrier is the one the block was issued to, "
    "which number portability makes unreliable.",
)
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
                    note=True,
                )
            ]
        return []
    findings = [Finding(label="well formed", value="yes" if phonenumbers.is_valid_number(parsed) else "no")]
    if region := phonenumbers.region_code_for_number(parsed):
        findings.append(Finding(label="region", value=region))
    if location := geocoder.description_for_number(parsed, "en"):
        findings.append(Finding(label="location", value=location))
    if name := carrier.name_for_number(parsed, "en"):  # empty for most landlines
        findings.append(Finding(label="carrier at issue", value=name))
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

# CVSS has four generations live in NVD at once and which one a record carries depends on when
# it was filed, so the newest present wins. Reading only cvssMetricV31 shows no severity at all
# on freshly published CVEs, which is exactly when severity matters most.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@fetcher(
    id="nvd-cve",
    accepts=[EntityType.CVE],
    name="NVD vulnerability record",
)
async def nvd_cve(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """NVD's keyless CVE API. Rate limited to 5 requests per 30s without a key, so one call only."""
    resp = await http.get(
        client,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "services.nvd.nist.gov",
        params={"cveId": value},
        allow=(404,),
    )
    if resp.status_code == 404:  # a malformed id, as distinct from an unassigned one
        return []
    data = resp.json()
    # An unassigned but well-formed id answers 200 with an empty result set, not a 404, so the
    # miss has to be read off the body. Branching on status alone would report every unknown CVE
    # as an error instead of as "no such record".
    entries = data.get("vulnerabilities") or []
    if not entries:
        return []
    cve = entries[0].get("cve", {})
    findings: list[Finding] = []
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en" and description.get("value"):
            findings.append(Finding(label="description", value=str(description["value"])))
            break
    metrics = cve.get("metrics") or {}
    for key in _CVSS_KEYS:
        entry = (metrics.get(key) or [None])[0]
        cvss = (entry or {}).get("cvssData") or {}
        if cvss.get("baseScore") is not None:
            severity = cvss.get("baseSeverity", "")
            findings.append(Finding(label="severity", value=f"{cvss['baseScore']} {severity}".strip()))
            if vector := cvss.get("vectorString"):
                findings.append(Finding(label="cvss vector", value=str(vector)))
            break
    if kev := cve.get("cisaExploitAdd"):
        # Known exploited in the wild, which is the single most actionable field NVD carries.
        findings.append(Finding(label="CISA KEV since", value=str(kev)))
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            cwe = str(description.get("value", ""))
            if cwe.startswith("CWE-"):
                findings.append(Finding(label="weakness", value=cwe))
    for label, key in (("published", "published"), ("last modified", "lastModified"), ("status", "vulnStatus")):
        if got := cve.get(key):
            findings.append(Finding(label=label, value=str(got)))
    return findings


def _sats(value: int) -> str:
    return f"{value:,} sats ({value / 1e8:.8f} BTC)"


@fetcher(
    id="mempool-space-tx",
    accepts=[EntityType.TX_HASH],
    name="Bitcoin transaction",
    note="Bitcoin only. An Ethereum hash reads as nothing found here; see the Ethereum panel.",
)
async def mempool_tx(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Bitcoin transaction via the keyless Esplora API. A hash that is not Bitcoin's reads empty."""
    resp = await http.get(
        client, f"https://mempool.space/api/tx/{quote(value, safe='')}", "mempool.space", allow=(404, 400)
    )
    # 404 and 400 come back as text/plain, so the status has to be checked before json() is
    # touched. 400 is "not 64 hex" and 404 is "no such transaction"; neither is an error.
    if resp.status_code in (400, 404):
        return []
    data = resp.json()
    status = data.get("status") or {}
    confirmed = bool(status.get("confirmed"))
    findings = [Finding(label="confirmed", value="yes" if confirmed else "no, still in the mempool")]
    if confirmed:
        # These keys are absent entirely while a transaction is unconfirmed, rather than null.
        for label, key in (("block height", "block_height"), ("block time", "block_time")):
            if (got := status.get(key)) is not None:
                findings.append(Finding(label=label, value=str(got)))
    if (fee := data.get("fee")) is not None:
        findings.append(Finding(label="fee", value=_sats(int(fee))))
    outputs = data.get("vout") or []
    if total := sum(int(o.get("value") or 0) for o in outputs):
        findings.append(Finding(label="output total", value=_sats(total)))
    findings.append(Finding(label="inputs / outputs", value=f"{len(data.get('vin') or [])} / {len(outputs)}"))
    for out in outputs[:10]:
        if address := out.get("scriptpubkey_address"):
            findings.append(Finding(label="output address", value=str(address)))
    return findings


@fetcher(
    id="blockscout-tx",
    accepts=[EntityType.TX_HASH],
    name="Ethereum transaction",
    note="Ethereum only. A Bitcoin hash reads as nothing found here; see the Bitcoin panel.",
)
async def blockscout_tx(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Ethereum transaction via Blockscout. Paired with the Bitcoin one because a bare 64-hex
    hash does not say which chain it belongs to, so both are asked and the misses read empty."""
    tx = value if value.lower().startswith("0x") else f"0x{value}"
    resp = await http.get(
        client,
        f"https://eth.blockscout.com/api/v2/transactions/{quote(tx, safe='')}",
        "eth.blockscout.com",
        allow=(404, 422),
    )
    if resp.status_code in (404, 422):
        return []
    data = resp.json()
    findings: list[Finding] = []
    for label, key in (("result", "result"), ("block", "block_number"), ("timestamp", "timestamp")):
        if got := data.get(key):
            findings.append(Finding(label=label, value=str(got)))
    for label, key in (("from", "from"), ("to", "to")):
        if address := (data.get(key) or {}).get("hash"):
            findings.append(Finding(label=label, value=str(address)))
    if (wei := data.get("value")) is not None:
        amount = f"{int(wei) / 1e18:.18f}".rstrip("0").rstrip(".") or "0"
        findings.append(Finding(label="value", value=f"{amount} ETH"))
    return findings


@fetcher(
    id="mempool-space-btc",
    accepts=[EntityType.BTC_ADDRESS],
    name="Bitcoin address",
)
async def mempool_address(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """Bitcoin address activity via the keyless Esplora API."""
    resp = await http.get(
        client, f"https://mempool.space/api/address/{quote(value, safe='')}", "mempool.space", allow=(400,)
    )
    if resp.status_code == 400:  # text/plain, and means the address itself is malformed
        return []
    data = resp.json()
    chain = data.get("chain_stats") or {}
    pending = data.get("mempool_stats") or {}
    received, sent = int(chain.get("funded_txo_sum") or 0), int(chain.get("spent_txo_sum") or 0)
    count = int(chain.get("tx_count") or 0)
    if not count and not int(pending.get("tx_count") or 0):
        # Every valid address exists implicitly, so there is no such thing as "not found" here.
        # Saying "no on-chain activity" is the truthful reading; "nothing found" would imply the
        # address is unknown rather than simply unused.
        return [Finding(label="note", value="valid address with no on-chain activity", note=True)]
    findings = [
        Finding(label="balance", value=_sats(received - sent)),
        Finding(label="total received", value=_sats(received)),
        Finding(label="total sent", value=_sats(sent)),
        Finding(label="transactions", value=str(count)),
    ]
    if unconfirmed := int(pending.get("tx_count") or 0):
        findings.append(Finding(label="unconfirmed", value=str(unconfirmed)))
    return findings
