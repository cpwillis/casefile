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
    """The templates used to re-express this rule without the casefold, so HTTPS:// linked in an
    export and rendered as plain text in the app. One shared filter now decides."""
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
    assert "<style>" in out  # inline css, no external assets
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
    """Export renders what you kept, not a fresh scrape. Nothing else may leak in.

    Asserted as a set rather than as absent strings: naming two sources that happen not to be
    in the fixture would still pass if export invented a third.
    """
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
    """CC BY-SA asks for attribution where the material is used. An exported file is the one
    artifact that leaves the machine without vendor/WMN-LICENCE.txt beside it."""
    out = export_case(WMN_CASE, fmt)
    assert "WhatsMyName" in out
    assert "CC BY-SA 4.0" in out


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_an_export_with_no_whatsmyname_finding_carries_no_credit(fmt):
    """Attribution follows the material, so a case that used none must not claim to."""
    assert "WhatsMyName" not in export_case(CASE, fmt)


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_a_joined_case_names_every_identifier_and_attributes_every_finding(fmt):
    """A case spans identifiers, so an export that flattened them would put a domain's DNS
    records beside a username's profile hits with nothing saying which was which."""
    out = export_case(JOINED, fmt)
    assert "acme.example" in out
    assert "Acme-Example" in out
    assert "192.0.2.10" in out
    assert "username" in out and "domain" in out


def test_markdown_escapes_a_hostile_finding_value():
    """The only thing stopping a third-party value from injecting raw HTML into an exported .md
    and retargeting the link it sits in. Nothing covered it: _md could be replaced with the
    identity function and the whole suite stayed green."""
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
