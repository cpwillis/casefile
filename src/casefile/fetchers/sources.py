"""Concrete fetchers. Importing this module registers them; one of them needs a key."""

import asyncio
import ipaddress
import re
from urllib.parse import quote

import httpx
import phonenumbers
from phonenumbers import PhoneNumberFormat

from casefile.config import get_key
from casefile.fetchers import Finding, NeedsKey, RateLimited, fetcher, http
from casefile.types import EntityType

_DNS_TYPES = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS"}
# 0 is an answer, 3 is an authoritative "no such name"; anything else means the resolver could not tell us.
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
    failed: list[str] = []
    last_exc: Exception | None = None
    for qtype in types:
        # DoH answers 200 for SERVFAIL, and one query can 429 or drop; either way one bad query must not discard
        # the records the others returned.
        try:
            resp = await http.fetch(
                client,
                "https://cloudflare-dns.com/dns-query",
                params={"name": name, "type": qtype},
                headers={"accept": "application/dns-json"},
            )
            data = resp.json()
        except (RateLimited, httpx.HTTPError) as exc:
            failed.append(f"{qtype} {type(exc).__name__}")
            last_exc = exc
            continue
        status = data.get("Status", 0)
        if status == 3:
            absent += 1
        elif status != 0:
            failed.append(f"{qtype} {_DNS_RCODES.get(status, status)}")
            continue
        for row in data.get("Answer", []):
            label = _DNS_TYPES.get(row.get("type"), str(row.get("type")))
            findings.append(Finding(label=label, value=row.get("data", "")))
    if absent and absent + len(failed) == len(types):
        return [Finding(label="note", value="NXDOMAIN: this name does not exist in DNS", note=True)]
    if failed and not findings:  # nothing resolved: re-raise the real error so a 429 still reads as rate-limited
        raise last_exc if last_exc else RuntimeError(f"resolver returned {', '.join(failed)}")
    if failed:
        findings.insert(0, Finding(label="note", value=f"no answer for {', '.join(failed)}", note=True))
    return findings


def _vcard_name(entity: dict) -> str | None:
    """jCard is a nested array: ["vcard", [["fn", {}, "text", "Some Org"]]], so the name is dug out positionally."""
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
    resp = await http.fetch(client, f"https://rdap.org/{kind}/{quote(key, safe='')}")
    data = resp.json()
    findings: list[Finding] = []
    if handle := data.get("handle"):
        findings.append(Finding(label="handle", value=str(handle)))
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


# A wildcard-heavy domain returns tens of thousands of names: one multi-megabyte cache row, unbounded.
_CRTSH_LIMIT = 500


@fetcher(
    id="crtsh",
    accepts=[EntityType.DOMAIN],
    name="crt.sh certificates",
    note="Names seen in public certificate transparency logs. A name here need not still resolve.",
)
async def crtsh(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.fetch(client, "https://crt.sh/", params={"q": value, "output": "json"})
    names: set[str] = set()
    for row in resp.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)
    shown = sorted(names)[:_CRTSH_LIMIT]
    findings = [Finding(label="subdomain", value=n, url=f"https://{n}") for n in shown]
    if len(names) > len(shown):
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
    # is_global is False for private, loopback, link-local, CGNAT and the documentation ranges, v4 and v6.
    if not address.is_global:
        # Skipped, not empty: 10.0.0.1 answers 200 with junk, and "nothing found" would claim an answer we never got.
        return [Finding(label="note", value="not a public address, so InternetDB was not queried", note=True)]
    resp = await http.fetch(
        client,
        f"https://internetdb.shodan.io/{quote(value, safe='')}",
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
    resp = await http.fetch(
        client,
        f"https://api.github.com/users/{quote(value, safe='')}",
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
    resp = await http.fetch(
        client,
        "https://www.wikidata.org/w/api.php",
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
    kind = _HASHLOOKUP_PATHS.get(len(value))
    if kind is None:
        return []
    resp = await http.fetch(
        client,
        f"https://hashlookup.circl.lu/lookup/{kind}/{quote(value, safe='')}",
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
    resp = await http.fetch(
        client,
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
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
    # Local import: the geocoding and carrier tables cost ~160ms to load, paid on every run otherwise.
    from phonenumbers import carrier, geocoder, timezone

    try:
        parsed = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        # The _phone detector only yields digit strings, so a parse failure without "+" is a missing country code.
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

# NVD carries four CVSS generations at once, so the newest present wins; V31-only shows nothing on new CVEs.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@fetcher(
    id="nvd-cve",
    accepts=[EntityType.CVE],
    name="NVD vulnerability record",
)
async def nvd_cve(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """NVD's keyless CVE API. Rate limited to 5 requests per 30s without a key, so one call only."""
    resp = await http.fetch(
        client,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": value},
        allow=(404,),
    )
    if resp.status_code == 404:  # a malformed id, as distinct from an unassigned one
        return []
    data = resp.json()
    # An unassigned but well-formed id answers 200 with an empty result set, not a 404, so read the miss off the body.
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
    resp = await http.fetch(client, f"https://mempool.space/api/tx/{quote(value, safe='')}", allow=(404, 400))
    # 400 ("not 64 hex") and 404 come back as text/plain, so check the status before touching json().
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
    """Ethereum transaction via Blockscout. A bare 64-hex hash names no chain, so both chains are asked."""
    tx = value if value.lower().startswith("0x") else f"0x{value}"
    resp = await http.fetch(
        client,
        f"https://eth.blockscout.com/api/v2/transactions/{quote(tx, safe='')}",
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
        # Integer arithmetic: 18 decimals do not survive a float, which rendered 0.1 ETH as 0.100000000000000006.
        whole, frac = divmod(int(wei), 10**18)
        amount = f"{whole}.{frac:018d}".rstrip("0").rstrip(".") or "0"
        findings.append(Finding(label="value", value=f"{amount} ETH"))
    return findings


@fetcher(
    id="mempool-space-btc",
    accepts=[EntityType.BTC_ADDRESS],
    name="Bitcoin address",
)
async def mempool_address(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.fetch(client, f"https://mempool.space/api/address/{quote(value, safe='')}", allow=(400,))
    if resp.status_code == 400:  # text/plain, and means the address itself is malformed
        return []
    data = resp.json()
    chain = data.get("chain_stats") or {}
    pending = data.get("mempool_stats") or {}
    received, sent = int(chain.get("funded_txo_sum") or 0), int(chain.get("spent_txo_sum") or 0)
    count = int(chain.get("tx_count") or 0)
    if not count and not int(pending.get("tx_count") or 0):
        # Every valid address exists implicitly, so "nothing found" would wrongly imply the address is unknown.
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


_CF_DOH = "https://cloudflare-dns.com/dns-query"


async def _doh(client: httpx.AsyncClient, name: str, qtype: str, *, resolver=_CF_DOH, **extra) -> dict:
    """One DoH JSON query. Returns the decoded answer; the caller reads Status, AD and Answer."""
    resp = await http.fetch(
        client, resolver, params={"name": name, "type": qtype, **extra}, headers={"accept": "application/dns-json"}
    )
    return resp.json()


_TXT_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


async def _txt(client: httpx.AsyncClient, name: str) -> list[str]:
    """TXT strings for a name. DoH quotes each 255-byte chunk of a record, so the chunks are joined back up."""
    data = await _doh(client, name, "TXT")
    rows = [r.get("data", "") for r in data.get("Answer") or [] if r.get("type") == 16]
    return ["".join(_TXT_CHUNK.findall(raw)) or raw for raw in rows]


def _tags(record: str) -> dict[str, str]:
    """`k=v; k=v` as a dict, keys lowered: DMARC records use this shape."""
    pairs = (part.strip().split("=", 1) for part in record.split(";") if "=" in part)
    return {k.strip().lower(): v.strip() for k, v in pairs}


_SPF_ALL = {"-all": "fail (-all)", "~all": "softfail (~all)", "?all": "neutral (?all)", "+all": "allows anyone (+all)"}


@fetcher(
    id="mail",
    accepts=[EntityType.DOMAIN],
    name="Email security (DNS)",
    note="SPF, DMARC, MTA-STS and BIMI as published in DNS. Absent here means unpublished, not misconfigured.",
)
async def mail(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    names = (value, f"_dmarc.{value}", f"_mta-sts.{value}", f"default._bimi.{value}")
    got = await asyncio.gather(*(_txt(client, n) for n in names), return_exceptions=True)
    failed = [n for n, r in zip(names, got, strict=True) if isinstance(r, BaseException)]
    if len(failed) == len(names):  # nothing answered: re-raise so a 429 still reads as rate-limited
        raise got[0]
    root, dmarc, mta_sts, bimi = (r if isinstance(r, list) else [] for r in got)
    findings: list[Finding] = []
    if failed:
        findings.append(Finding(label="note", value=f"no answer for {', '.join(failed)}", note=True))
    if spf := next((r for r in root if r.lower().startswith("v=spf1")), None):
        terms = spf.lower().split()[1:]
        # a bare `all` is `+all`
        policy = next(
            (_SPF_ALL.get(t if t[0] in "+-~?" else f"+{t}") for t in terms if t.lstrip("+-~?") == "all"), None
        )
        findings.append(Finding(label="SPF policy", value=policy or "no all mechanism"))
        findings += [Finding(label="SPF include", value=t.split(":", 1)[1]) for t in terms if t.startswith("include:")]
    else:
        findings.append(Finding(label="SPF", value="not published"))
    if rec := next((r for r in dmarc if r.lower().startswith("v=dmarc1")), None):
        tags = _tags(rec)
        findings.append(Finding(label="DMARC policy", value=tags.get("p", "none given")))
        if sub := tags.get("sp"):
            findings.append(Finding(label="DMARC subdomain policy", value=sub))
        for key, label in (("rua", "DMARC rua"), ("ruf", "DMARC ruf")):
            findings += [Finding(label=label, value=a.strip()) for a in tags.get(key, "").split(",") if a.strip()]
    else:
        findings.append(Finding(label="DMARC", value="not published"))
    has_sts = any(r.lower().startswith("v=stsv1") for r in mta_sts)
    findings.append(Finding(label="MTA-STS", value="published" if has_sts else "not published"))
    has_bimi = any(r.lower().startswith("v=bimi1") for r in bimi)
    findings.append(Finding(label="BIMI", value="published" if has_bimi else "not published"))
    return findings


_DS_ALGORITHMS = {
    5: "RSASHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}


@fetcher(
    id="dnssec",
    accepts=[EntityType.DOMAIN],
    name="DNSSEC (Cloudflare)",
    note="Whether the parent zone holds a DS record, and whether Cloudflare's resolver validated the chain.",
)
async def dnssec(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    data = await _doh(client, value, "DS", do=1)
    status = data.get("Status", 0)
    if status == 3:
        return [Finding(label="note", value="NXDOMAIN: this name does not exist in DNS", note=True)]
    if status == 2:  # a validation failure and a dead nameserver look the same from here
        note = "SERVFAIL: the resolver could not answer, a broken DNSSEC chain is one cause"
        return [Finding(label="note", value=note, note=True)]
    if status != 0:
        raise RuntimeError(f"resolver returned {_DNS_RCODES.get(status, status)}")
    ds = [r for r in data.get("Answer") or [] if r.get("type") == 43]  # do=1 also returns the RRSIG rows
    if not ds:
        return [Finding(label="DNSSEC", value="not signed (no DS record at the parent)")]
    findings = [
        Finding(label="DNSSEC", value="signed (DS record at the parent)"),
        Finding(label="validated", value="yes" if data.get("AD") else "no, the resolver did not set AD"),
    ]
    for row in ds:
        parts = str(row.get("data", "")).split()  # key tag, algorithm, digest type, digest
        if len(parts) >= 3 and parts[1].isdigit():
            algorithm = _DS_ALGORITHMS.get(int(parts[1]), "unassigned")
            findings.append(Finding(label="DS algorithm", value=f"{parts[1]} ({algorithm})"))
            findings.append(Finding(label="DS key tag", value=parts[0]))
    return findings


# The CDX API measured 9-17s a call; httpx's 20s read timeout would cut the slow ones, so this request gets its own.
_CDX_TIMEOUT = httpx.Timeout(40.0, connect=5.0)


def _capture_date(stamp: str) -> str:
    return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[8:10]}:{stamp[10:12]}:{stamp[12:14]} UTC"


@fetcher(
    id="wayback",
    accepts=[EntityType.DOMAIN, EntityType.URL],
    name="Wayback Machine",
    note="Internet Archive captures of this exact address. Slow: the archive can take 20s or more to answer.",
)
async def wayback(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    async def edge(limit: int) -> str | None:
        resp = await http.fetch(
            client,
            "https://web.archive.org/cdx/search/cdx",
            params={"url": value, "output": "json", "fl": "timestamp", "limit": limit},
            timeout=_CDX_TIMEOUT,
        )
        rows = resp.json()
        return rows[1][0] if len(rows) > 1 and rows[1] else None  # row 0 is the header; [] means never archived

    async with asyncio.timeout(40):
        first, last = await asyncio.gather(edge(1), edge(-1))
    if not first or not last:
        return []
    return [
        Finding(label="first capture", value=_capture_date(first), url=f"https://web.archive.org/web/{first}/{value}"),
        Finding(label="last capture", value=_capture_date(last), url=f"https://web.archive.org/web/{last}/{value}"),
        Finding(label="calendar", value="all captures", url=f"https://web.archive.org/web/*/{value}"),
    ]


@fetcher(
    id="tranco",
    accepts=[EntityType.DOMAIN],
    name="Tranco rank",
    note="A research ranking of the most visited domains. Unranked is common and says nothing about the domain.",
)
async def tranco(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.fetch(client, f"https://tranco-list.eu/api/ranks/domain/{quote(value, safe='')}")
    ranks = resp.json().get("ranks") or []  # newest first; empty means not in the list
    if not ranks:
        return []
    latest, oldest = ranks[0], ranks[-1]
    findings = [Finding(label="rank", value=f"{latest['rank']:,} on {latest['date']}")]
    if len(ranks) > 1:
        delta = oldest["rank"] - latest["rank"]  # a smaller number is a better rank, so a drop in number is a rise
        word = "rose" if delta > 0 else "fell"
        trend = f"{word} from {oldest['rank']:,} on {oldest['date']}" if delta else f"unchanged since {oldest['date']}"
        findings.append(Finding(label="trend", value=trend))
    return findings


@fetcher(
    id="hsts-preload",
    accepts=[EntityType.DOMAIN],
    name="HSTS preload list",
    note="Whether browsers ship this domain as HTTPS-only. Not on the list is the norm, not a fault.",
)
async def hsts_preload(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    resp = await http.fetch(client, "https://hstspreload.org/api/v2/status", params={"domain": value})
    status = str(resp.json().get("status", "unknown"))
    shown = {"unknown": "not on the preload list", "pending": "pending, submitted but not yet in browsers"}
    url = f"https://hstspreload.org/?domain={quote(value, safe='')}"
    return [Finding(label="HSTS preload", value=shown.get(status, status), url=url)]


@fetcher(
    id="ip-geo",
    accepts=[EntityType.IP],
    name="IP geolocation (ipwho.is)",
    note="Where a database places the address. City is a guess, and a VPN or CDN address says nothing of the user.",
)
async def ip_geo(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    data = (await http.fetch(client, f"https://ipwho.is/{quote(value, safe='')}")).json()
    if not data.get("success"):  # eg "Reserved range": an answer about the address, not a failure of the source
        message = str(data.get("message") or "ipwho.is has no data for this address")
        return [Finding(label="note", value=message, note=True)]
    conn = data.get("connection") or {}
    rows = (
        ("country", data.get("country")),
        ("region", data.get("region")),
        ("city", data.get("city")),
        ("ASN", f"AS{conn['asn']}" if conn.get("asn") else None),
        ("org", conn.get("org")),
        ("isp", conn.get("isp")),
        ("domain", conn.get("domain")),
        ("ip type", data.get("type")),
    )
    return [Finding(label=label, value=str(v)) for label, v in rows if v]


@fetcher(
    id="urlhaus",
    accepts=[EntityType.DOMAIN, EntityType.URL, EntityType.IP],
    name="URLhaus",
    note="A known-BAD corpus of URLs reported for malware. A hit means it was reported, not that it is live now.",
)
async def urlhaus(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    """abuse.ch requires an Auth-Key for URLhaus too, so a key is needed, as for MalwareBazaar."""
    key = get_key("ABUSECH_AUTH_KEY")
    if not key:
        raise NeedsKey("set ABUSECH_AUTH_KEY in .env to enable URLhaus")
    is_url = entity_type is EntityType.URL
    resp = await http.fetch(
        client,
        f"https://urlhaus-api.abuse.ch/v1/{'url' if is_url else 'host'}/",
        method="POST",
        data={"url" if is_url else "host": value},
        headers={"Auth-Key": key},
        allow=(401,),
    )
    payload = resp.json() if resp.status_code != 401 else {}
    if resp.status_code == 401 or payload.get("query_status") == "unauthorized":
        raise NeedsKey("ABUSECH_AUTH_KEY was rejected by abuse.ch")
    if payload.get("query_status") != "ok":
        return []  # no_results, invalid_host and friends mean looked-and-found-nothing
    reference = payload.get("urlhaus_reference")
    findings: list[Finding] = []
    if not is_url:
        findings.append(Finding(label="URL count", value=str(payload.get("url_count", 0)), url=reference))
    rows = [payload] if is_url else payload.get("urls") or []
    tags: set[str] = set()
    for row in rows[:10]:
        detail = ", ".join(str(row[k]) for k in ("url_status", "threat") if row.get(k))
        link = row.get("urlhaus_link") or reference
        findings.append(Finding(label="url", value=f"{row.get('url', '')} ({detail})", url=link))
        tags.update(str(t) for t in row.get("tags") or [])
    return findings + [Finding(label="tag", value=t) for t in sorted(tags)]


_SINKHOLE = ipaddress.ip_network("0.0.0.0/8")
_RESOLVERS = (
    ("AdGuard", "https://dns.adguard-dns.com/resolve"),
    ("Cloudflare Security", "https://security.cloudflare-dns.com/dns-query"),
    ("Cloudflare Family", "https://family.cloudflare-dns.com/dns-query"),
)


def _addresses(data: dict) -> list[str]:
    return [r.get("data", "") for r in data.get("Answer") or [] if r.get("type") in (1, 28)]


def _is_sinkhole(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip in _SINKHOLE if ip.version == 4 else ip.is_unspecified


@fetcher(
    id="blocklists",
    accepts=[EntityType.DOMAIN],
    name="DNS blocklists",
    note="Whether filtering resolvers refuse to resolve it. Blocked is a resolver's policy, not proof of harm.",
)
async def blocklists(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    queries = [_doh(client, value, "A")] + [_doh(client, value, "A", resolver=url) for _, url in _RESOLVERS]
    control, *filtered = await asyncio.gather(*queries, return_exceptions=True)
    resolves = (
        isinstance(control, dict)
        and control.get("Status") == 0
        and any(not _is_sinkhole(a) for a in _addresses(control))
    )
    if not resolves:  # without a resolving control a block cannot be told from a name that never resolved
        return [Finding(label="note", value="cannot tell: the unfiltered resolver gave no real answer", note=True)]
    findings = []
    for (name, _), data in zip(_RESOLVERS, filtered, strict=True):
        if not isinstance(data, dict) or data.get("Status") not in (0, 3):
            verdict = "no answer from this resolver"
        elif data["Status"] == 3:
            verdict = "blocked (NXDOMAIN)"
        elif addresses := _addresses(data):
            verdict = "blocked (sinkhole)" if all(_is_sinkhole(a) for a in addresses) else "not blocked"
        else:
            verdict = "no answer from this resolver"
        findings.append(Finding(label=name, value=verdict))
    return findings
