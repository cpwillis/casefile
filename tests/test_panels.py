from helpers import client, stub_result

import casefile.fetchers.sources  # noqa: F401 -- register the real fetchers
from casefile.fetchers import Finding, State, fetchers_for
from casefile.types import EntityType


def test_domain_has_the_three_fetchers_registered():
    ids = [r.id for r in fetchers_for(EntityType.DOMAIN)]
    assert {"dns", "rdap", "crtsh"} <= set(ids)


def test_panel_route_renders_a_state(monkeypatch):
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding(label="A", value="192.0.2.10")))
    resp = client.get("/panel/dns", params={"v": "example.com", "t": "domain"})
    assert resp.status_code == 200
    assert "192.0.2.10" in resp.text
    assert 'data-state="ok"' in resp.text


def test_panel_empty_and_error_render_differently(monkeypatch):
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(state=State.EMPTY))
    empty = client.get("/panel/e", params={"v": "example.com", "t": "domain"}).text
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(state=State.ERROR, detail="boom"))
    error = client.get("/panel/x", params={"v": "example.com", "t": "domain"}).text
    assert 'data-state="empty"' in empty
    assert 'data-state="error"' in error
    assert "boom" in error


def test_panel_escapes_untrusted_findings(monkeypatch):
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("x", "<script>alert(1)</script>")))
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_panel_with_bad_type_does_not_crash():
    resp = client.get("/panel/dns", params={"v": "example.com", "t": "not-a-type"})
    assert resp.status_code == 200
    assert 'data-state="error"' in resp.text


def test_panel_rejects_type_the_source_does_not_accept():
    resp = client.get("/panel/rdap", params={"v": "someone@example.com", "t": "email"})
    assert resp.status_code == 200
    assert 'data-state="error"' in resp.text
    assert "rdap does not accept email" in resp.text


def test_panel_does_not_link_a_javascript_scheme_url(monkeypatch):
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("x", "click me", "javascript:alert(1)")))
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'href="javascript:' not in text
    assert "click me" in text


def test_panel_still_links_an_http_url(monkeypatch):
    monkeypatch.setattr(
        "casefile.web.app.run_cached", stub_result(Finding("x", "sub.example.com", "https://sub.example.com"))
    )
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'href="https://sub.example.com"' in text


def test_whatsmyname_panel_renders_the_required_attribution(monkeypatch):
    """CC BY-SA requires attribution where the material is used, so the UI must carry it."""
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("Hit", "tech", "https://h.test/x")))
    text = client.get("/panel/whatsmyname", params={"v": "someone", "t": "username"}).text
    assert "WhatsMyName" in text
    assert "CC BY-SA 4.0" in text


def test_panel_refuses_a_cross_site_request():
    """A page the user visits must not be able to drive hundreds of lookups from their IP."""
    resp = client.get(
        "/panel/dns",
        params={"v": "example.com", "t": "domain"},
        headers={"sec-fetch-site": "cross-site"},
    )
    assert resp.status_code == 200
    assert 'data-state="error"' in resp.text
    assert "cross-site" in resp.text


def test_a_pivotable_finding_gets_a_search_link_and_a_free_form_one_does_not(monkeypatch):
    """An IP is the next query; a WhatsMyName site category is not, and putting an arrow on every
    row would make the affordance meaningless."""
    monkeypatch.setattr(
        "casefile.web.app.run_cached",
        stub_result(Finding("A", "192.0.2.10"), Finding("category", "coding")),
    )
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'href="/q?v=192.0.2.10"' in text
    assert 'href="/q?v=coding"' not in text


def test_a_panel_asks_the_store_once_regardless_of_how_many_findings_it_has(monkeypatch):
    """Star state used to cost one sqlite connection per finding row, which is linear in a
    number no source is obliged to keep small. crtsh can return tens of thousands."""
    import sqlite3

    from casefile.cases import Star, star
    from casefile.types import EntityType

    star(EntityType.DOMAIN, "example.com", Star("dns", "A", "v7"))
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(*(Finding("A", f"v{i}") for i in range(200))))

    opened = 0
    real = sqlite3.connect

    def counting(*args, **kwargs):
        nonlocal opened
        opened += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", counting)
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text

    assert opened == 1, f"{opened} connections for 200 rows"
    assert text.count("star starred") == 1, "the one starred finding lost its state"


def test_a_long_finding_list_gets_a_filter_and_a_short_one_does_not(monkeypatch):
    """The volume is in the findings, not the links: crtsh returns up to 500 subdomains and a
    WhatsMyName run returns hundreds of hits, and neither could be narrowed down."""
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(*(Finding("A", f"v{i}") for i in range(30))))
    long = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'class="filter findings-filter"' in long
    assert "filter 30 findings" in long

    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("A", "192.0.2.10")))
    short = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert "findings-filter" not in short


def test_the_findings_filter_targets_its_own_list(monkeypatch):
    """Two panels on a page must not filter each other, so the id is derived from the target and
    the source rather than from the source alone."""
    import re

    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(*(Finding("A", f"v{i}") for i in range(30))))
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    target = re.search(r'data-filters="([^"]+)"', text).group(1)
    assert f'<ul class="findings" id="{target}"' in text


def test_a_panel_is_named_and_carries_its_caveat(monkeypatch):
    """A source id is not a name, and polarity is not self-evident: a hit in a known-good corpus
    and a hit in a malware corpus look identical and mean opposite things."""
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("known good file", "x")))
    text = client.get("/panel/hashlookup", params={"v": "d" * 32, "t": "hash"}).text
    assert "CIRCL hashlookup" in text
    assert "known-GOOD" in text


def test_a_panel_can_be_focused_after_its_own_swap(monkeypatch):
    """refresh and Run destroy the button that triggered them, so htmx has nothing to re-focus.
    The panel carries the id and the tabindex instead."""
    monkeypatch.setattr("casefile.web.app.run_cached", stub_result(Finding("A", "192.0.2.10")))
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'tabindex="-1"' in text
    assert 'id="star-' in text  # the same derived id the result page renders
