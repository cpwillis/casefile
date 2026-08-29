import json

import pytest

from casefile.cases import Case, Star
from casefile.export import FORMATS, export_case

CASE = Case(
    id="domain:example.com",
    entity_type="domain",
    value="example.com",
    created_at=1_756_000_000.0,
    updated_at=1_756_000_500.0,
    star_count=2,
    stars=(
        Star(source_id="crtsh", label="subdomain", value="a.example.com", url="https://a.example.com"),
        Star(source_id="dns", label="A", value="192.0.2.10"),
    ),
)


def test_every_format_is_reachable():
    assert set(FORMATS) == {"md", "json", "html"}


def test_the_web_layer_knows_a_media_type_for_every_format():
    """FORMATS is the one list; a format the download route cannot type would 500 on click."""
    from casefile.web.app import _MEDIA

    assert set(_MEDIA) == set(FORMATS)


@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_every_format_names_the_target_and_its_stars(fmt):
    out = export_case(CASE, fmt)
    assert "example.com" in out
    assert "a.example.com" in out
    assert "192.0.2.10" in out


def test_markdown_groups_by_source_and_links_urls():
    out = export_case(CASE, "md")
    assert "# example.com" in out
    assert "## crtsh" in out
    assert "[a.example.com](https://a.example.com)" in out
    assert "192.0.2.10" in out  # no url, so plain text


def test_json_is_parseable_and_stable():
    payload = json.loads(export_case(CASE, "json"))
    assert payload["target"] == "example.com"
    assert payload["entity_type"] == "domain"
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
        id="domain:x.example",
        entity_type="domain",
        value="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(Star(source_id="dns", label="A", value="<script>alert(1)</script>"),),
    )
    out = export_case(hostile, "html")
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_drops_a_dangerous_url_scheme():
    hostile = Case(
        id="domain:x.example",
        entity_type="domain",
        value="x.example",
        created_at=0.0,
        updated_at=0.0,
        star_count=1,
        stars=(Star(source_id="dns", label="A", value="ok", url="javascript:alert(1)"),),
    )
    out = export_case(hostile, "html")
    assert "javascript:" not in out


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="pdf"):
        export_case(CASE, "pdf")


def test_export_never_includes_anything_unstarred():
    """Export renders what you kept, not a fresh scrape. Nothing else may leak in."""
    out = export_case(CASE, "md")
    assert "rdap" not in out
    assert "whatsmyname" not in out
