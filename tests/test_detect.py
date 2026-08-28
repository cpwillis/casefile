import pytest

from casefile.detect import TIER1, TIER2
from casefile.types import EntityType

TIER1_DETECTORS = dict(TIER1)


@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        (EntityType.IP, "192.0.2.10", "192.0.2.10"),
        (EntityType.IP, "2001:db8::1", "2001:db8::1"),
        (EntityType.IP, "192.0.2.10/24", None),
        (EntityType.IP, "999.0.2.10", None),
        (EntityType.ASN, "AS64496", "AS64496"),
        (EntityType.ASN, "as64496", "AS64496"),
        (EntityType.ASN, "64496", None),
        (EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "abc123", None),
        (EntityType.CVE, "cve-2021-44228", "CVE-2021-44228"),
        (EntityType.CVE, "CVE-2021-44228", "CVE-2021-44228"),
        (EntityType.MAC, "00:1b:44:11:3a:b7", "00:1b:44:11:3a:b7"),
        (EntityType.MAC, "00-1B-44-11-3A-B7", "00:1b:44:11:3a:b7"),
        (EntityType.COORDINATES, "-33.8688, 151.2093", "-33.8688,151.2093"),
        (EntityType.COORDINATES, "91.0, 0.0", None),
        (EntityType.ICAO24, "7c6b2d", "7c6b2d"),
        (EntityType.BTC_ADDRESS, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
        (
            EntityType.ETH_ADDRESS,
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x52908400098527886e0f7030069857d2e4169ee7",
        ),
    ],
)
def test_tier1_detector(entity_type, raw, expected):
    assert TIER1_DETECTORS[entity_type](raw) == expected


TIER2_DETECTORS = dict(TIER2)


@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        (EntityType.EMAIL, "Someone@Example.COM", "someone@example.com"),
        (EntityType.EMAIL, "not-an-email", None),
        (EntityType.URL, "https://example.com/a?b=c", "https://example.com/a?b=c"),
        (EntityType.URL, "example.com", None),
        (EntityType.DOMAIN, "Example.COM", "example.com"),
        (EntityType.DOMAIN, "sub.example.co.uk", "sub.example.co.uk"),
        (EntityType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
        (EntityType.DOMAIN, "no_underscores.com", None),
        (EntityType.DOMAIN, "trailing.", None),
        (EntityType.PHONE, "+61 2 9374 4000", "+61293744000"),
        (EntityType.PHONE, "(02) 9374 4000", "0293744000"),
        (EntityType.PHONE, "123", None),
        (EntityType.PHONE, "192.0.2.10", None),
        (EntityType.PHONE, "1.800.555.0199", "18005550199"),
        (EntityType.VIN, "1HGCM82633A004352", "1HGCM82633A004352"),
        (EntityType.VIN, "1HGCM82633A00435I", None),
        (EntityType.IMO, "IMO 9074729", "9074729"),
        (EntityType.MMSI, "503000000", "503000000"),
        (EntityType.TAIL_NUMBER, "vh-oqa", "VH-OQA"),
        (EntityType.TAIL_NUMBER, "AS64496", None),
    ],
)
def test_tier2_detector(entity_type, raw, expected):
    assert TIER2_DETECTORS[entity_type](raw) == expected
