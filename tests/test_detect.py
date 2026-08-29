import pytest

from casefile.detect import TIER1, TIER2, detect
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
        (EntityType.ASN, "as007", "AS7"),
        (EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.HASH, "abc123", None),
        (EntityType.CVE, "cve-2021-44228", "CVE-2021-44228"),
        (EntityType.CVE, "CVE-2021-44228", "CVE-2021-44228"),
        (EntityType.MAC, "00:1b:44:11:3a:b7", "00:1b:44:11:3a:b7"),
        (EntityType.MAC, "00-1B-44-11-3A-B7", "00:1b:44:11:3a:b7"),
        (EntityType.MAC, "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        (EntityType.COORDINATES, "-33.8688, 151.2093", "-33.8688,151.2093"),
        (EntityType.COORDINATES, "91.0, 0.0", None),
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
        (EntityType.EMAIL, "Someone@Example.COM", "Someone@example.com"),
        (EntityType.EMAIL, "not-an-email", None),
        (EntityType.URL, "https://example.com/a?b=c", "https://example.com/a?b=c"),
        (EntityType.URL, "example.com", None),
        (EntityType.DOMAIN, "Example.COM", "example.com"),
        (EntityType.DOMAIN, "sub.example.co.uk", "sub.example.co.uk"),
        (EntityType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
        (EntityType.DOMAIN, "under_score.example", "under_score.example"),
        (EntityType.DOMAIN, "_dmarc.example.com", "_dmarc.example.com"),
        (EntityType.DOMAIN, "example.com.", "example.com"),
        # UTS46, not the stdlib IDNA2003 codec, which would map this to strasse.de
        (EntityType.DOMAIN, "straße.de", "xn--strae-oqa.de"),
        (EntityType.DOMAIN, "faß.de", "xn--fa-hia.de"),
        (EntityType.DOMAIN, "trailing.", None),
        (EntityType.PHONE, "+61 2 5550 0000", "+61255500000"),
        (EntityType.PHONE, "(02) 5550 0000", "0255500000"),
        (EntityType.PHONE, "123", None),
        (EntityType.PHONE, "192.0.2.10", None),
        (EntityType.PHONE, "1.800.555.0199", "18005550199"),
        (EntityType.VIN, "1HGCM82633A004352", "1HGCM82633A004352"),
        (EntityType.VIN, "1HGCM82633A00435I", None),
        (EntityType.IMO, "IMO 9074729", "9074729"),
        (EntityType.MMSI, "503000000", "503000000"),
        (EntityType.TAIL_NUMBER, "vh-oqa", "VH-OQA"),
        (EntityType.TAIL_NUMBER, "AS64496", None),
        (EntityType.ICAO24, "7c6b2d", "7c6b2d"),
        (EntityType.ICAO24, "400931", "400931"),
    ],
)
def test_tier2_detector(entity_type, raw, expected):
    assert TIER2_DETECTORS[entity_type](raw) == expected


def types_of(raw):
    return [c.type for c in detect(raw)]


def test_unambiguous_input_suppresses_free_form():
    assert types_of("192.0.2.10") == [EntityType.IP]


def test_domain_readings_are_pinned_in_order():
    assert types_of("example.com") == [
        EntityType.DOMAIN,
        EntityType.USERNAME,
        EntityType.PERSON,
        EntityType.COMPANY,
    ]


def test_url_also_yields_its_host_as_a_domain():
    result = detect("https://example.com/a?b=c")
    assert result[0].type is EntityType.URL
    domain = next(c for c in result if c.type is EntityType.DOMAIN)
    assert domain.value == "example.com"


def test_url_without_a_resolvable_host_yields_no_domain():
    assert EntityType.DOMAIN not in types_of("https://localhost/x")


def test_bare_word_is_free_form_only():
    assert types_of("cpwillis") == [EntityType.USERNAME, EntityType.PERSON, EntityType.COMPANY]


def test_two_words_are_person_and_company_not_username():
    result = types_of("Ada Lovelace")
    assert EntityType.USERNAME not in result
    assert result == [EntityType.PERSON, EntityType.COMPANY]


def test_values_are_normalised_per_candidate():
    (candidate,) = detect("CVE-2021-44228")
    assert candidate.value == "CVE-2021-44228"
    domain = next(c for c in detect("Example.COM") if c.type is EntityType.DOMAIN)
    assert domain.value == "example.com"


def test_empty_whitespace_and_punctuation_yield_nothing():
    assert detect("") == ()
    assert detect("   ") == ()
    assert detect("!!!") == ()


def test_no_duplicate_types():
    result = types_of("example.com")
    assert len(result) == len(set(result))


def test_malformed_url_never_crashes_detect():
    for bad in ["http://[", "https://[::1", "http://a]b", "http://]"]:
        assert detect(bad) == ()  # no candidate, and crucially no exception


def test_dictionary_word_keeps_free_form_readings():
    # 'facade' is 6 hex chars; ICAO24 must not suppress the username/person/company reading
    result = types_of("facade")
    assert EntityType.USERNAME in result
    assert EntityType.PERSON in result
    assert EntityType.ICAO24 in result
    assert EntityType.TAIL_NUMBER not in result  # 6-hex is icao24, not a tail number


def test_all_digit_icao24_is_recognised():
    assert any(c.type is EntityType.ICAO24 and c.value == "400931" for c in detect("400931"))


def test_md5_hash_is_not_also_a_btc_address():
    result = types_of("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d")
    assert EntityType.HASH in result
    assert EntityType.BTC_ADDRESS not in result


def test_unicode_digits_are_not_treated_as_numbers():
    assert detect("٩٨٧٨٩٢٨٩١") == ()  # Arabic-Indic digits are not phone/mmsi/etc


def test_url_candidate_lowercases_scheme_and_host():
    (url,) = [c for c in detect("HTTP://EXAMPLE.COM/Path") if c.type is EntityType.URL]
    assert url.value == "http://example.com/Path"
    domain = next(c for c in detect("HTTP://EXAMPLE.COM/Path") if c.type is EntityType.DOMAIN)
    assert domain.value == "example.com"


def test_control_characters_are_rejected():
    assert detect("a\x00b@x.example") == ()


def test_idna_deviation_does_not_become_a_different_domain():
    """straße.de and strasse.de are different registrable domains.

    The stdlib "idna" codec is IDNA2003 and maps the first to the second, which would silently
    point a user at somebody else's host. UTS46 keeps them distinct.
    """
    (sharp,) = [c for c in detect("straße.de") if c.type is EntityType.DOMAIN]
    (double_s,) = [c for c in detect("strasse.de") if c.type is EntityType.DOMAIN]
    assert sharp.value != double_s.value
    assert sharp.value == "xn--strae-oqa.de"
