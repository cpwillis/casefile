from casefile.report import build_report


def test_sections_follow_detection_order():
    sections = build_report("example.com")
    assert [s.type for s in sections] == ["domain", "username", "person", "company"]


def test_links_carry_encoded_urls():
    (section,) = [s for s in build_report("example.com") if s.type == "domain"]
    crtsh = next(link for link in section.links if link.id == "crtsh")
    assert crtsh.url == "https://crt.sh/?q=example.com"


def test_unrecognised_input_yields_no_sections():
    assert build_report("!!!") == ()
