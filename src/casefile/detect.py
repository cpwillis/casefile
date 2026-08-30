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


def _tx_hash(s: str) -> str | None:
    """32-byte hex, with or without 0x. Separate from HASH: bare 64-hex is also a SHA-256 for malware lookups."""
    body = s[2:] if s[:2].lower() == "0x" else s
    return body.lower() if re.fullmatch(r"(?i)[0-9a-f]{64}", body) else None


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
    # A URL with userinfo (https://user@host) is not an email: read as one it leaked credentials into every link.
    if _has_control(s) or "://" in s:
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
        # Not idna: it rejects underscores, and _dmarc.example.com is a routine DNS pivot.
        candidate = s.lower()
    else:
        try:
            # UTS46, not the stdlib "idna" codec: IDNA2003 maps ß to ss, so straße.de becomes a different real host.
            candidate = idna.encode(s, uts46=True).decode("ascii")
        except idna.IDNAError:
            return None
    if not re.fullmatch(rf"{_LABEL}(?:\.{_LABEL})+", candidate):
        return None
    if candidate.split(".")[-1].isdigit():
        return None
    return candidate


def _phone(s: str) -> str | None:
    """Regex-only; the phone fetcher does the real parsing with libphonenumber."""
    if _ip(s):  # 192.0.2.10 is seven digits and all-dots, which would otherwise pass
        return None
    plus = s.strip().startswith("+")
    digits = re.sub(r"[^0-9]", "", s)
    if not 7 <= len(digits) <= 15:
        return None
    if not re.fullmatch(r"[\s()+\-.0-9]+", s.strip()):
        return None
    return f"+{digits}" if plus else digits


# ISO 3779: position 9 is the check digit, X means 10. Letter values restart at J and at S; I, O and Q are absent.
_VIN_VALUES = {c: int(c) for c in "0123456789"}
_VIN_VALUES.update(dict(zip("ABCDEFGH", (1, 2, 3, 4, 5, 6, 7, 8), strict=True)))
_VIN_VALUES.update(dict(zip("JKLMNPR", (1, 2, 3, 4, 5, 7, 9), strict=True)))
_VIN_VALUES.update(dict(zip("STUVWXYZ", (2, 3, 4, 5, 6, 7, 8, 9), strict=True)))
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _vin_check_digit_ok(vin: str) -> bool:
    total = sum(_VIN_VALUES[c] * w for c, w in zip(vin, _VIN_WEIGHTS, strict=True))
    expected = total % 11
    return vin[8] == ("X" if expected == 10 else str(expected))


def _vin(s: str) -> str | None:
    """Check digit enforced: a transposed character otherwise reads as a valid VIN, and every source then misses."""
    if not re.fullmatch(r"(?i)[A-HJ-NPR-Z0-9]{17}", s):
        return None
    vin = s.upper()
    return vin if _vin_check_digit_ok(vin) else None


def _imo(s: str) -> str | None:
    """Same reasoning as _vin: the check digit rejects typos that would otherwise look like a real IMO."""
    m = re.fullmatch(r"(?i)(?:imo[\s:]*)?([0-9]{7})", s.strip())
    if not m:
        return None
    digits = m.group(1)
    checksum = sum(int(d) * w for d, w in zip(digits[:6], range(7, 1, -1), strict=True))
    return digits if checksum % 10 == int(digits[6]) else None


def _mmsi(s: str) -> str | None:
    return s if re.fullmatch(r"[0-9]{9}", s) else None


# A hyphenated registration (G-ABCD, VH-OQA) or a US N-number, the one scheme without one. The hyphen stops "octocat".
_TAIL = re.compile(r"(?i)^(?:[a-z]{1,2}-[a-z0-9]{1,5}|N[0-9]{1,5}[a-z]{0,2})$")


def _tail_number(s: str) -> str | None:
    if _asn(s) or _icao24(s):  # AS64496 is an ASN and 6-hex is an ICAO24, neither is a tail number
        return None
    return s.upper() if _TAIL.match(s) else None


def _domain_from_url(value: str) -> str | None:
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    return _domain(host) if host else None


# ICAO24 is TIER2, not TIER1: bare 6-hex collides with words (facade, decade), so it must not suppress TIER3.
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
    (EntityType.TX_HASH, _tx_hash),
)

_NAMEISH = r"[A-Za-z][A-Za-z0-9 .,&'’\-]{1,59}"


def _username(s: str) -> str | None:
    s = s.strip().lstrip("@")  # @octocat is how handles are written; it is still the handle
    if " " in s:
        return None
    return s if re.fullmatch(r"[A-Za-z0-9._-]{2,39}", s) and any(c.isalpha() for c in s) else None


def _nameish(s: str) -> str | None:
    """Person and company are indistinguishable in the string itself, so both are offered and the catalogue decides."""
    s = s.strip()
    return s if re.fullmatch(_NAMEISH, s) else None


TIER3: tuple[tuple[EntityType, Detector], ...] = (
    (EntityType.USERNAME, _username),
    (EntityType.PERSON, _nameish),
    (EntityType.COMPANY, _nameish),
)


# Almost any string reads as a person or company, so a value with only these readings is not worth a pivot.
FREE_FORM = frozenset({EntityType.USERNAME, EntityType.PERSON, EntityType.COMPANY})


def is_pivotable(value: str) -> bool:
    """Whether a value is a structured identifier worth searching from: a discovered IP or CVE is the next query."""
    return any(c.type not in FREE_FORM for c in detect(value))


def detect(raw: str) -> tuple[Candidate, ...]:
    """Ranked readings, most constrained first. Tier 1 suppresses tier 3; tier 2 does not (example.com is both)."""
    value = raw.strip()
    if not value:
        return ()

    tier1 = tuple(Candidate(t, v) for t, d in TIER1 if (v := d(value)) is not None)
    tier2 = tuple(Candidate(t, v) for t, d in TIER2 if (v := d(value)) is not None)

    have = {c.type for c in tier2}
    if EntityType.URL in have and EntityType.DOMAIN not in have and (host := _domain_from_url(value)):
        tier2 = (*tier2, Candidate(EntityType.DOMAIN, host))
    # An email carries a domain and often a handle, both real pivots; a URL already yields its host the same way.
    if EntityType.EMAIL in have:
        local, _, host = value.strip().partition("@")
        if EntityType.DOMAIN not in have and (derived := _domain(host)):
            tier2 = (*tier2, Candidate(EntityType.DOMAIN, derived))
        if EntityType.USERNAME not in have and (handle := _username(local)):
            tier2 = (*tier2, Candidate(EntityType.USERNAME, handle))

    if tier1:
        return tier1 + tier2

    tier3 = tuple(Candidate(t, v) for t, d in TIER3 if (v := d(value)) is not None)
    return tier2 + tier3
