import json

import pytest

from casefile.cases import Case, Star, Target
from casefile.export import FORMATS, export_case

CASE = Case(
    id="abc123",
    name="example.com",
    created_at=1_756_000_000.0,
    updated_at=1_756_000_500.0,
    star_count=2,
    targets=(Target(entity_type="domain", value="example.com", star_count=2),),
    stars=(
        Star("crtsh", "subdomain", "a.example.com", "https://a.example.com", "domain", "example.com"),
        Star("dns", "A", "192.0.2.10", None, "domain", "example.com"),
    ),
)

# The model's reason for existing: one investigation, two identifiers that share no format.
JOINED = Case(
    id="def456",
    name="acme-example",
    created_at=0.0,
    updated_at=0.0,
    star_count=2,
    targets=(
        Target(entity_type="username", value="acme-example", star_count=1),
        Target(entity_type="domain", value="acme.example", star_count=1),
    ),
    stars=(
        Star("github", "profile", "Acme-Example", "https://github.example/x", "username", "acme-example"),
        Star("dns", "A", "192.0.2.10", None, "domain", "acme.example"),
    ),
)


def test_every_format_is_reachable():
    assert set(FORMATS) == {"md", "json", "html"}


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_every_format_has_both_a_renderer_and_a_media_type(fmt):
    """One table declares both, so the download route cannot know a format the renderer lacks."""
    from casefile.export import media_type

    assert export_case(CASE, fmt)
    assert media_type(fmt)


def test_an_uppercase_scheme_is_treated_the_same_everywhere():
    """One shared filter decides: a re-expressed rule without the casefold dropped HTTPS:// in the app."""
    from casefile.export import safe_url

    assert safe_url("HTTPS://EXAMPLE.COM/x") == "HTTPS://EXAMPLE.COM/x"
    assert safe_url("JavaScript:alert(1)") is None


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_every_format_names_the_target_and_its_stars(fmt):
    out = export_case(CASE, fmt)
    assert "example.com" in out
    assert "a.example.com" in out
    assert "192.0.2.10" in out


def test_markdown_groups_by_source_and_links_urls():
    out = export_case(CASE, "md")
    assert "# example.com" in out
    assert "### crtsh" in out
    assert "[a.example.com](https://a.example.com)" in out
    assert "192.0.2.10" in out  # no url, so plain text


def test_json_is_parseable_and_stable():
    payload = json.loads(export_case(CASE, "json"))
    assert payload["name"] == "example.com"
    assert [t["entity_type"] for t in payload["targets"]] == ["domain"]
    assert len(payload["stars"]) == 2
    assert {s["source_id"] for s in payload["stars"]} == {"crtsh", "dns"}
    assert payload["stars"][0]["url"] == "https://a.example.com"


def test_html_is_self_contained():
    out = export_case(CASE, "html")
    assert out.lstrip().startswith("<!doctype html>")
    assert "<style>" in out
    assert "<link" not in out
    assert "<script" not in out


def test_html_escapes_untrusted_finding_values():
    hostile = Case(
        id="hostile",
        name="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(Star("dns", "A", "<script>alert(1)</script>", None, "domain", "x.example"),),
    )
    out = export_case(hostile, "html")
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_drops_a_dangerous_url_scheme():
    hostile = Case(
        id="hostile",
        name="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(Star("dns", "A", "ok", "javascript:alert(1)", "domain", "x.example"),),
    )
    out = export_case(hostile, "html")
    assert "javascript:" not in out


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="pdf"):
        export_case(CASE, "pdf")


def test_export_never_includes_anything_unstarred():
    """Export renders what you kept. Asserted as a set: naming absent sources still passes if export invented one."""
    import re

    out = export_case(CASE, "md")
    assert set(re.findall(r"^### (.+)$", out, re.M)) == {s.source_id for s in CASE.stars}
    assert {f["value"] for f in json.loads(export_case(CASE, "json"))["stars"]} == {s.value for s in CASE.stars}


WMN_CASE = Case(
    id="wmn1",
    name="octocat",
    created_at=0.0,
    updated_at=0.0,
    star_count=1,
    targets=(Target(entity_type="username", value="octocat", star_count=1),),
    stars=(Star("whatsmyname", "GitHub", "coding", "https://github.example/x", "username", "octocat"),),
)


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_a_whatsmyname_finding_carries_its_licence_credit(fmt):
    """CC BY-SA asks for attribution, and an export is the artifact that leaves without WMN-LICENCE.txt beside it."""
    out = export_case(WMN_CASE, fmt)
    assert "WhatsMyName" in out
    assert "CC BY-SA 4.0" in out


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_an_export_with_no_whatsmyname_finding_carries_no_credit(fmt):
    """Attribution follows the material, so a case that used none must not claim to."""
    assert "WhatsMyName" not in export_case(CASE, fmt)


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_a_joined_case_names_every_identifier_and_attributes_every_finding(fmt):
    """A flattened export would put a domain's DNS records beside a username's profile hits, unattributed."""
    out = export_case(JOINED, fmt)
    assert "acme.example" in out
    assert "Acme-Example" in out
    assert "192.0.2.10" in out
    assert "username" in out and "domain" in out


def test_markdown_escapes_a_hostile_finding_value():
    """_md could be the identity function with the suite green: a value can retarget the link it sits in."""
    hostile = Case(
        id="hostile",
        name="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        targets=(Target(entity_type="domain", value="x.example"),),
        stars=(Star("dns", "A", "<b>x</b>](http://evil.example)", "https://ok.example", "domain", "x.example"),),
    )
    out = export_case(hostile, "md")
    assert "](http://evil.example)" not in out, "the value broke out of its markdown link"
    assert "<b>" not in out, "raw html survived into the markdown"
    assert "https://ok.example" in out


def test_markdown_escapes_a_hostile_label_and_the_case_name():
    hostile = Case(
        id="hostile2",
        name="[click](http://evil.example)",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        targets=(),
        stars=(Star("dns", "**bold**", "v", None, "domain", "x.example"),),
    )
    out = export_case(hostile, "md")
    assert "](http://evil.example)" not in out
    assert "**bold**:" not in out, "a label escaped into markdown emphasis"


def test_markdown_url_cannot_break_out_of_its_link():
    """A finding url with a paren closes the Markdown link early, letting a second attacker-chosen link in. crtsh
    builds urls straight from CT log SANs, so this is reachable without a crafted request."""
    hostile = Case(
        id="h",
        name="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(
            Star(
                "crtsh", "subdomain", "a.example", "https://ok.example/)[x](javascript:alert(1))", "domain", "x.example"
            ),
        ),
    )
    out = export_case(hostile, "md")
    assert "](javascript:" not in out


def test_a_url_with_whitespace_or_controls_is_not_linked():
    """No real url has a newline or space; one that does injects Markdown headings or breaks an HTML attribute."""
    from casefile.export import safe_url

    assert safe_url("https://ok.example/\n## heading") is None
    assert safe_url("https://ok.example/a b") is None
    assert safe_url("https://ok.example/café") == "https://ok.example/café"  # non-ascii path stays a link


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_exports_carry_the_source_polarity_note(fmt):
    """A hit in a known-good corpus and a hit in a malware corpus look identical; the note is what tells them apart."""
    import casefile.fetchers.sources  # noqa: F401 -- registers the sources so source_note resolves

    case = Case(
        id="c",
        name="x",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(Star("hashlookup", "known good file", "f", None, "hash", "d" * 32),),
    )
    out = export_case(case, fmt)
    assert "known-GOOD" in out or "legitimate" in out


def test_a_url_with_a_backslash_is_not_linked():
    """A backslash escapes the Markdown link's closing paren; no real url carries a raw one."""
    from casefile.export import safe_url

    assert safe_url("https://ok.example/a\\b") is None
