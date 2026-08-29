import pytest
from helpers import client

SAME = {"sec-fetch-site": "same-origin"}
STAR = {"t": "domain", "v": "example.com", "source_id": "dns", "label": "A", "value": "192.0.2.10", "url": ""}


def test_star_requires_a_same_origin_header():
    """A page you visit while casefile runs must not be able to write to your cases."""
    assert client.post("/star", data=STAR, headers={"sec-fetch-site": "cross-site"}).status_code == 403


def test_star_refuses_a_request_with_no_sec_fetch_site():
    """Stricter than the read-only panel guard: only this app's own page may mutate."""
    assert client.post("/star", data=STAR).status_code == 403


def test_star_is_not_reachable_by_get():
    assert client.get("/star", params=STAR).status_code == 405


def test_starring_then_unstarring_round_trips():
    from casefile.cases import list_cases

    first = client.post("/star", data=STAR, headers=SAME)
    assert first.status_code == 200
    assert "★" in first.text  # filled star
    assert len(list_cases()) == 1

    # The button declares intent rather than toggling, so a stale tab cannot un-save silently.
    second = client.post("/star", data=dict(STAR, action="unstar"), headers=SAME)
    assert "☆" in second.text  # hollow again
    assert list_cases() == ()


def test_a_stale_tab_cannot_unsave_by_re_saving():
    """Two tabs on the same page: clicking save twice must not cascade the case away."""
    from casefile.cases import list_cases

    client.post("/star", data=STAR, headers=SAME)
    client.post("/star", data=STAR, headers=SAME)  # a stale tab repeating "save"
    assert len(list_cases()) == 1


def test_deleting_a_case_removes_it():
    from casefile.cases import list_cases

    client.post("/star", data=STAR, headers=SAME)
    resp = client.post("/case/domain:example.com/delete", headers=SAME, follow_redirects=False)
    assert resp.status_code == 303
    assert list_cases() == ()


def test_deleting_a_case_refuses_cross_site():
    client.post("/star", data=STAR, headers=SAME)
    assert client.post("/case/domain:example.com/delete", headers={"sec-fetch-site": "cross-site"}).status_code == 403


def test_a_foreign_host_is_refused_on_every_route_even_when_same_origin():
    """Sec-Fetch-Site alone does not survive DNS rebinding, so Host is pinned too.

    Asserted across every route rather than the two that used to carry a hand-pasted guard:
    the pin is middleware now precisely so a new route cannot quietly opt out of it. /panel is
    in the list on purpose, being the only route that makes outbound requests from your IP.
    """
    evil = {"host": "evil.example"}
    assert client.post("/star", data=STAR, headers={**SAME, **evil}).status_code == 400
    for path in (
        "/",
        "/q?v=example.com",
        "/cases",
        "/case/domain:example.com",
        "/case/domain:example.com/export.md",
        "/panel/dns?v=example.com&t=domain",
    ):
        assert client.get(path, headers=evil).status_code == 400, f"{path} accepted a foreign Host"


def test_export_filename_survives_a_unicode_target():
    """case.value is third-party influenced and reaches a response header.

    A raw unicode value used to raise UnicodeEncodeError in the header encoder, 500ing every
    export of an ordinary internationalised email address.
    """
    client.post("/star", data=dict(STAR, t="email", v="a@\u65e5\u672c\u8a9e.example"), headers=SAME)
    from casefile.cases import list_cases

    (case,) = list_cases()
    resp = client.get(f"/case/{case.id}/export.md")
    assert resp.status_code == 200
    disposition = resp.headers["content-disposition"]
    disposition.encode("latin-1")  # raises if non-latin-1 leaked into the header
    assert "\r" not in disposition and "\n" not in disposition and disposition.count('"') == 2


def test_star_rejects_an_unknown_entity_type():
    bad = dict(STAR, t="not-a-type")
    assert client.post("/star", data=bad, headers=SAME).status_code == 400


def test_cases_page_lists_a_saved_case():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get("/cases").text
    assert "example.com" in text
    assert "1 saved" in text


def test_index_shows_where_you_left_off():
    assert "Where you left off" not in client.get("/").text
    client.post("/star", data=STAR, headers=SAME)
    assert "Where you left off" in client.get("/").text


def test_case_detail_shows_only_starred_findings():
    """The page renders the store, never a fresh fetch, so its source list is exactly the stars."""
    import re

    client.post("/star", data=STAR, headers=SAME)
    text = client.get("/case/domain:example.com").text
    assert "192.0.2.10" in text
    shown = {m.split("\u00b7")[0].strip() for m in re.findall(r'<span class="f-label">([^<]+)</span>', text)}
    assert shown == {"dns"}, f"case page shows sources that were never starred: {shown}"


def test_missing_case_falls_back_to_the_list():
    assert "no longer exists" in client.get("/case/domain:nope.example").text


@pytest.mark.parametrize(
    ("fmt", "needle"), [("md", "# example.com"), ("json", '"target"'), ("html", "<!doctype html>")]
)
def test_export_downloads_each_format(fmt, needle):
    client.post("/star", data=STAR, headers=SAME)
    resp = client.get(f"/case/domain:example.com/export.{fmt}")
    assert resp.status_code == 200
    assert needle in resp.text
    assert "attachment" in resp.headers["content-disposition"]


def test_export_rejects_an_unknown_format():
    client.post("/star", data=STAR, headers=SAME)
    assert client.get("/case/domain:example.com/export.pdf").status_code == 404


def test_an_unwritable_store_shows_the_failure_on_the_button(tmp_path, monkeypatch):
    """htmx does not swap a 5xx, so a save that failed must come back as a visibly failed button
    rather than as a status code the page silently ignores."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    from casefile.cases import cases_path

    cases_path().parent.mkdir(parents=True, exist_ok=True)
    cases_path().write_bytes(b"this is not a sqlite database")
    resp = client.post("/star", data=STAR, headers=SAME)
    assert resp.status_code == 200
    assert "could not save" in resp.text
    assert 'aria-pressed="false"' in resp.text


def test_an_empty_search_returns_to_the_one_homepage():
    """Rendering index.html a second time without its context silently dropped the saved cases."""
    client.post("/star", data=STAR, headers=SAME)
    resp = client.get("/q", params={"v": "   "}, follow_redirects=True)
    assert "Where you left off" in resp.text
