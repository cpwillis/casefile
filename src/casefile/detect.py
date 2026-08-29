"""Input to ranked candidate types. Pure functions, no I/O."""

import re
from collections.abc import Callable
from ipaddress import ip_address
from urllib.parse import urlsplit

import idna

from casefile.types import Candidate, EntityType

Detector = Callable[[str], str | None]

_HASH_LENGTHS = {32, 40, 64}


def _has_control(s: str) -> bool:
    return any(ord(c) < 32 for c in s)


def _ip(s: str) -> str | None:
    try:
        return str(ip_address(s))
    except ValueError:
        return None


def _asn(s: str) -> str | None:
    m = re.fullmatch(r"(?i)as([0-9]{1,10})", s)
    return f"AS{int(m.group(1))}" if m else None  # int() drops leading zeros


def _hash(s: str) -> str | None:
    if len(s) in _HASH_LENGTHS and re.fullmatch(r"(?i)[0-9a-f]+", s):
        return s.lower()
    return None


def _cve(s: str) -> str | None:
    m = re.fullmatch(r"(?i)cve-([0-9]{4})-([0-9]{4,7})", s)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _mac(s: str) -> str | None:
    if re.fullmatch(r"(?i)[0-9a-f]{2}([:-][0-9a-f]{2}){5}", s):
        parts = re.split(r"[:-]", s)
    elif re.fullmatch(r"(?i)[0-9a-f]{4}(\.[0-9a-f]{4}){2}", s):  # Cisco dotted notation
        flat = s.replace(".", "")
        parts = [flat[i : i + 2] for i in range(0, 12, 2)]
    else:
        return None
    return ":".join(p.lower() for p in parts)


def _coordinates(s: str) -> str | None:
    m = re.fullmatch(r"\s*(-?[0-9]{1,3}(?:\.[0-9]+)?)\s*,\s*(-?[0-9]{1,3}(?:\.[0-9]+)?)\s*", s)
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return f"{m.group(1)},{m.group(2)}"


def _icao24(s: str) -> str | None:
    return s.lower() if re.fullmatch(r"(?i)[0-9a-f]{6}", s) else None


def _btc_address(s: str) -> str | None:
    if _hash(s):  # a hash-shaped hex string is a hash, not a base58 address
        return None
    if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", s):
        return s
    if re.fullmatch(r"(?i)bc1[02-9ac-hj-np-z]{11,71}", s):
        return s.lower()
    return None


def _eth_address(s: str) -> str | None:
    return s.lower() if re.fullmatch(r"(?i)0x[0-9a-f]{40}", s) else None


TIER1: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.IP, _ip),
    (EntityType.ASN, _asn),
    (EntityType.HASH, _hash),
    (EntityType.CVE, _cve),
    (EntityType.MAC, _mac),
    (EntityType.COORDINATES, _coordinates),
    (EntityType.BTC_ADDRESS, _btc_address),
    (EntityType.ETH_ADDRESS, _eth_address),
)

# Leading/trailing underscore allowed: _dmarc, _domainkey, _sip._tcp are routine DNS pivots.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"


def _email(s: str) -> str | None:
    if _has_control(s):
        return None
    m = re.fullmatch(r"([^@\s]+)@([^@\s]+\.[^@\s]+)", s)
    return f"{m.group(1)}@{m.group(2).lower()}" if m else None  # local-part is case-sensitive


def _url(s: str) -> str | None:
    if _has_control(s) or not re.match(r"(?i)https?://\S+$", s):
        return None
    try:
        parts = urlsplit(s)
        host = parts.hostname
    except ValueError:
        return None
    if host is None:
        return s
    netloc = host.lower()
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    if parts.username:
        auth = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{auth}@{netloc}"
    return parts._replace(scheme=parts.scheme.lower(), netloc=netloc).geturl()


def _domain(s: str) -> str | None:
    s = s.strip().rstrip(".")  # accept a trailing-dot FQDN
    if not s:
        return None
    if s.isascii():
        # Deliberately not routed through idna: it rejects underscores, and _dmarc.example.com
        # and _sip._tcp.example.com are routine DNS pivots we want to keep.
        candidate = s.lower()
    else:
        try:
            # UTS46, not the stdlib "idna" codec. The stdlib is IDNA2003 and maps ß to "ss", so
            # straße.de would silently normalise to strasse.de, a different real host.
            candidate = idna.encode(s, uts46=True).decode("ascii")
        except idna.IDNAError:
            return None
    if not re.fullmatch(rf"{_LABEL}(?:\.{_LABEL})+", candidate):
        return None
    if candidate.split(".")[-1].isdigit():
        return None
    return candidate


def _phone(s: str) -> str | None:
    """Regex-only. libphonenumber arrives in phase 4 with the fetcher that needs it."""
    if _ip(s):  # 192.0.2.10 is seven digits and all-dots, which would otherwise pass
        return None
    plus = s.strip().startswith("+")
    digits = re.sub(r"[^0-9]", "", s)
    if not 7 <= len(digits) <= 15:
        return None
    if not re.fullmatch(r"[\s()+\-.0-9]+", s.strip()):
        return None
    return f"+{digits}" if plus else digits


def _vin(s: str) -> str | None:
    return s.upper() if re.fullmatch(r"(?i)[A-HJ-NPR-Z0-9]{17}", s) else None


def _imo(s: str) -> str | None:
    m = re.fullmatch(r"(?i)(?:imo[\s:]*)?([0-9]{7})", s.strip())
    return m.group(1) if m else None


def _mmsi(s: str) -> str | None:
    return s if re.fullmatch(r"[0-9]{9}", s) else None


def _tail_number(s: str) -> str | None:
    if re.fullmatch(r"(?i)as[0-9]+", s):  # AS64496 is an ASN, not a tail number
        return None
    if re.fullmatch(r"(?i)[0-9a-f]{6}", s):  # 6-hex is an ICAO24, not a tail number
        return None
    return s.upper() if re.fullmatch(r"(?i)[a-z]{1,2}-?[a-z0-9]{1,5}", s) and any(c.isalpha() for c in s) else None


def _domain_from_url(value: str) -> str | None:
    """A URL is also a pivot on its host, so paste a URL and get the domain sources too."""
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    return _domain(host) if host else None


# ICAO24 lives in TIER2, not TIER1: a bare 6-hex string collides with dictionary words
# (facade, decade) and real usernames, so it must NOT suppress the free-form TIER3 readings.
TIER2: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.EMAIL, _email),
    (EntityType.URL, _url),
    (EntityType.DOMAIN, _domain),
    (EntityType.PHONE, _phone),
    (EntityType.VIN, _vin),
    (EntityType.IMO, _imo),
    (EntityType.MMSI, _mmsi),
    (EntityType.ICAO24, _icao24),
    (EntityType.TAIL_NUMBER, _tail_number),
)

_NAMEISH = r"[A-Za-z][A-Za-z0-9 .,&'’\-]{1,59}"


def _username(s: str) -> str | None:
    s = s.strip()
    if " " in s:
        return None
    return s if re.fullmatch(r"[A-Za-z0-9._-]{2,39}", s) and any(c.isalpha() for c in s) else None


def _nameish(s: str) -> str | None:
    """Person and company share this: nothing in the string itself separates the two readings,
    so both are offered and the catalogue decides what each is worth looking up in."""
    s = s.strip()
    return s if re.fullmatch(_NAMEISH, s) else None


TIER3: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.USERNAME, _username),
    (EntityType.PERSON, _nameish),
    (EntityType.COMPANY, _nameish),
)


def detect(raw: str) -> tuple[Candidate, ...]:
    """Ranked candidate readings of `raw`, most constrained first.

    Tier 3 is suppressed entirely when a tier-1 detector matches: an IP address is not a
    plausible person, and offering it as one is noise. Tier 2 does not suppress tier 3,
    because `example.com` genuinely is both a domain and a plausible company name.
    """
    value = raw.strip()
    if not value:
        return ()

    tier1 = tuple(Candidate(t, v) for t, d in TIER1 if (v := d(value)) is not None)
    tier2 = tuple(Candidate(t, v) for t, d in TIER2 if (v := d(value)) is not None)

    have = {c.type for c in tier2}
    if EntityType.URL in have and EntityType.DOMAIN not in have and (host := _domain_from_url(value)):
        tier2 = (*tier2, Candidate(EntityType.DOMAIN, host))

    if tier1:
        return tier1 + tier2

    tier3 = tuple(Candidate(t, v) for t, d in TIER3 if (v := d(value)) is not None)
    return tier2 + tier3
