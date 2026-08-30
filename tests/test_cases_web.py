import pytest
from helpers import bare_client, client

from casefile.cases import list_cases, load_case


def _saved_case_id():
    (case,) = list_cases()
    return case.id


SAME = {"sec-fetch-site": "same-origin"}
STAR = {"t": "domain", "v": "example.com", "source_id": "dns", "label": "A", "value": "192.0.2.10", "url": ""}


def test_star_refuses_a_request_with_no_sec_fetch_site():
    """A browser always sends the header, so its absence means the caller is not one."""
    assert bare_client.post("/star", data=STAR).status_code == 403


def test_star_is_not_reachable_by_get():
    assert client.get("/star", params=STAR).status_code == 405


def test_starring_then_unstarring_round_trips():
    first = client.post("/star", data=STAR, headers=SAME)
    assert first.status_code == 200
    assert "★" in first.text
    assert len(list_cases()) == 1

    # The button declares intent rather than toggling, so a stale tab cannot un-save silently.
    second = client.post("/star", data=dict(STAR, action="unstar"), headers=SAME)
    assert "☆" in second.text
    # The case stays: it holds the identifier, and removing that is what closes it.
    (case,) = list_cases()
    assert case.star_count == 0
    assert [t.value for t in case.targets] == ["example.com"]


def test_a_stale_tab_cannot_unsave_by_re_saving():
    """Two tabs on the same page: clicking save twice must not cascade the case away."""
    client.post("/star", data=STAR, headers=SAME)
    client.post("/star", data=STAR, headers=SAME)
    assert len(list_cases()) == 1


def test_deleting_a_case_removes_it():
    client.post("/star", data=STAR, headers=SAME)
    resp = client.post(f"/case/{_saved_case_id()}/delete", headers=SAME, follow_redirects=False)
    assert resp.status_code == 303
    assert list_cases() == ()


def test_a_foreign_host_is_refused_on_every_route_even_when_same_origin():
    """Sec-Fetch-Site alone does not survive DNS rebinding, so Host is pinned in middleware for every route.

    /panel is the highest-risk entry below: it is the one route that spends outbound egress from the user's IP.
    """
    evil = {"host": "evil.example"}
    assert client.post("/star", data=STAR, headers={**SAME, **evil}).status_code == 400
    for path in (
        "/",
        "/q?v=example.com",
        "/cases",
        "/case/anything",
        "/case/anything/export.md",
        "/panel/dns?v=example.com&t=domain",
    ):
        assert client.get(path, headers=evil).status_code == 400, f"{path} accepted a foreign Host"


def test_export_filename_survives_a_unicode_target():
    """Unescaped, a unicode value in content-disposition raises UnicodeEncodeError and 500s an ordinary export."""
    client.post("/star", data=dict(STAR, t="email", v="a@\u65e5\u672c\u8a9e.example"), headers=SAME)
    (case,) = list_cases()
    resp = client.get(f"/case/{case.id}/export.md")
    assert resp.status_code == 200
    disposition = resp.headers["content-disposition"]
    disposition.encode("latin-1")  # raises if non-latin-1 leaked into the header
    assert "\r" not in disposition and "\n" not in disposition and disposition.count('"') == 2
    assert "filename*=UTF-8''" in disposition  # the real unicode name is preserved, not only the ascii slug


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
    text = client.get(f"/case/{_saved_case_id()}").text
    assert "192.0.2.10" in text
    shown = {m.split("\u00b7")[0].strip() for m in re.findall(r'<span class="f-label">([^<]+)</span>', text)}
    assert shown == {"dns"}, f"case page shows sources that were never starred: {shown}"


def test_missing_case_falls_back_to_the_list():
    assert "no longer exists" in client.get("/case/never-existed").text


@pytest.mark.parametrize(("fmt", "needle"), [("md", "# example.com"), ("json", '"name"'), ("html", "<!doctype html>")])
def test_export_downloads_each_format(fmt, needle):
    client.post("/star", data=STAR, headers=SAME)
    resp = client.get(f"/case/{_saved_case_id()}/export.{fmt}")
    assert resp.status_code == 200
    assert needle in resp.text
    assert "attachment" in resp.headers["content-disposition"]


def test_export_rejects_an_unknown_format():
    client.post("/star", data=STAR, headers=SAME)
    assert client.get(f"/case/{_saved_case_id()}/export.pdf").status_code == 404


def test_an_unwritable_store_shows_the_failure_on_the_button(tmp_path, monkeypatch):
    """htmx does not swap a 5xx, so a failed save must come back as a 200 with a visibly failed button."""
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


SAVE = {"t": "username", "v": "acme-example"}


def test_save_this_search_creates_a_case_with_nothing_starred():
    resp = client.post("/save", data=SAVE, headers=SAME, follow_redirects=False)
    assert resp.status_code == 303
    (case,) = list_cases()
    assert case.name == "acme-example"
    assert case.star_count == 0


def test_a_second_search_can_be_joined_onto_the_same_case():
    client.post("/save", data=SAVE, headers=SAME)
    cid = list_cases()[0].id
    client.post("/save", data={"t": "domain", "v": "acme.example", "case_id": cid}, headers=SAME)
    (case,) = list_cases()
    assert {t.value for t in case.targets} == {"acme-example", "acme.example"}


def test_a_saved_search_says_so_on_the_result_page():
    client.post("/save", data=SAVE, headers=SAME)
    text = client.get("/q", params={"v": "acme-example"}).text
    assert "Saved to" in text
    assert "Save this identifier" not in text.split("Saved to")[0][-400:]


def test_an_unsaved_search_offers_to_save_and_to_join():
    client.post("/save", data=SAVE, headers=SAME)
    text = client.get("/q", params={"v": "example.com"}).text
    assert "Save this identifier" in text
    assert "acme-example" in text, "no way to join this search onto an existing case"


def test_a_case_can_be_renamed_from_its_page():
    client.post("/save", data=SAVE, headers=SAME)
    cid = list_cases()[0].id
    resp = client.post(f"/case/{cid}/rename", data={"name": "Acme investigation"}, headers=SAME, follow_redirects=False)
    assert resp.status_code == 303
    assert list_cases()[0].name == "Acme investigation"


def test_removing_a_target_from_the_result_page():
    client.post("/save", data=SAVE, headers=SAME)
    client.post("/save", data=dict(SAVE, action="remove"), headers=SAME)
    assert list_cases() == ()


def test_the_save_control_does_not_nest_a_form_inside_a_paragraph():
    """A browser closes an open <p> when a <form> starts inside it, which broke the control onto its own line."""
    import re

    client.post("/save", data=SAVE, headers=SAME)
    text = client.get("/q", params={"v": "acme-example"}).text
    for para in re.findall(r"<p\b[^>]*>.*?</p>", text, re.S):
        assert "<form" not in para, f"a form is nested inside a paragraph: {para[:120]}"


def test_one_finding_can_be_removed_from_the_case_page():
    """A source that has since changed cannot be un-starred from a result page."""
    client.post("/star", data=STAR, headers=SAME)
    client.post("/star", data=dict(STAR, label="MX", value="0 ."), headers=SAME)
    cid = _saved_case_id()
    assert load_case(cid).star_count == 2

    resp = client.post("/star", data=dict(STAR, action="unstar", back=cid), headers=SAME, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/case/{cid}"
    remaining = load_case(cid)
    assert [s.label for s in remaining.stars] == ["MX"]
    assert [t.value for t in remaining.targets] == ["example.com"], "the identifier went with the finding"


def test_the_case_page_offers_a_remove_control_per_finding():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get(f"/case/{_saved_case_id()}").text
    assert text.count('name="action" value="unstar"') == 1


def test_the_case_page_shows_the_timestamps_the_store_already_keeps():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get(f"/case/{_saved_case_id()}").text
    assert "opened" in text and "last change" in text
    assert "UTC" in text


def test_a_finding_that_is_itself_an_identifier_offers_a_pivot():
    client.post("/star", data=STAR, headers=SAME)
    text = client.get(f"/case/{_saved_case_id()}").text
    assert 'class="pivot" href="/q?v=192.0.2.10"' in text


def test_the_star_button_id_matches_across_both_render_paths():
    """htmx re-focuses after an outerHTML swap only if the replacement carries the same id, and two paths render it."""
    import re

    from helpers import stub_result

    import casefile.web.app as appmod
    from casefile.fetchers import Finding

    original = appmod.run_cached
    appmod.run_cached = stub_result(Finding("A", "192.0.2.10"))
    try:
        panel = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    finally:
        appmod.run_cached = original
    in_panel = re.search(r'<button id="(star-[0-9a-f]+)"', panel).group(1)

    swapped = client.post("/star", data=STAR, headers=SAME).text
    on_its_own = re.search(r'<button id="(star-[0-9a-f]+)"', swapped).group(1)
    assert in_panel == on_its_own, "the swap replaces the button with a differently-identified one"


def test_the_star_buttons_accessible_name_does_not_change_with_its_state():
    """aria-pressed carries the state, so a name that flipped too would announce 'Remove..., pressed': contradictory."""
    saved = client.post("/star", data=STAR, headers=SAME).text
    unsaved = client.post("/star", data=dict(STAR, action="unstar"), headers=SAME).text
    for text in (saved, unsaved):
        assert 'aria-label="Save this finding"' in text
    assert 'aria-pressed="true"' in saved
    assert 'aria-pressed="false"' in unsaved


def test_removing_the_last_identifier_warns_and_lands_where_the_loss_is_visible():
    """One unguarded click destroyed a named case and left you on a page showing no sign it had happened."""
    client.post("/save", data=SAVE, headers=SAME)
    cid = _saved_case_id()
    client.post(f"/case/{cid}/rename", data={"name": "Tuesday intrusion"}, headers=SAME)
    client.post("/star", data={**STAR, "t": "username", "v": "acme-example"}, headers=SAME)

    page = client.get("/q", params={"v": "acme-example"}).text
    assert "onsubmit" in page and "confirm(" in page, "the result-page remove has no confirmation"
    assert "the case and its" in page, "the confirm does not say the case itself will be deleted"

    resp = client.post("/save", data=dict(SAVE, action="remove"), headers=SAME, follow_redirects=False)
    assert resp.headers["location"] == "/cases", "you were sent back to a search page, not to the loss"
    assert list_cases() == ()


def test_a_case_name_is_bounded():
    """Unbounded, a name reached the add-to select on every result page and stretched the layout past 4000px."""
    from casefile.cases import CaseStoreError, rename_case

    client.post("/save", data=SAVE, headers=SAME)
    cid = _saved_case_id()
    with pytest.raises(CaseStoreError, match="at most"):
        rename_case(cid, "A" * 600)
    resp = client.post(f"/case/{cid}/rename", data={"name": "A" * 600}, headers=SAME)
    assert resp.status_code == 400
    assert "text/html" in resp.headers["content-type"], "a failed rename returned a bare text page"
    assert list_cases()[0].name == "acme-example"


def test_a_long_name_cannot_stretch_the_result_page():
    client.post("/save", data=SAVE, headers=SAME)
    cid = _saved_case_id()
    client.post(f"/case/{cid}/rename", data={"name": "N" * 120}, headers=SAME)
    text = client.get("/q", params={"v": "example.com"}).text
    assert "N" * 120 not in text, "the full name reached the select untruncated"


def test_a_blank_identifier_is_refused():
    from casefile.cases import CaseStoreError, save_target
    from casefile.types import EntityType

    with pytest.raises(CaseStoreError):
        save_target(EntityType.USERNAME, "   ")


def test_the_dashboard_does_not_print_a_case_name_twice():
    client.post("/save", data=SAVE, headers=SAME)
    text = client.get("/cases").text
    assert text.count("acme-example") == 1


def test_one_save_control_per_page_not_one_per_reading():
    """Per reading, saving example.com four ways made four dashboard rows nothing could tell apart."""
    assert client.get("/q", params={"v": "example.com"}).text.count("Save this identifier") == 1


def test_the_dashboard_distinguishes_cases_that_share_a_name():
    """A username and a company can be the same word, so the reading is what tells the rows apart."""
    for t in ("username", "company"):
        client.post("/save", data={"t": t, "v": "smith"}, headers=SAME)
    text = client.get("/cases").text
    assert "username" in text and "company" in text


def test_removing_an_identifier_from_a_case_page_returns_to_that_case():
    client.post("/save", data=SAVE, headers=SAME)
    cid = _saved_case_id()
    client.post("/save", data={"t": "domain", "v": "second.example", "case_id": cid}, headers=SAME)
    resp = client.post(
        "/save",
        data={"t": "domain", "v": "second.example", "action": "remove", "back": cid},
        headers=SAME,
        follow_redirects=False,
    )
    assert resp.headers["location"] == f"/case/{cid}", "you were sent to a search for what you discarded"


def test_deleting_a_case_that_does_not_exist_says_so():
    """Reporting a delete that never happened is the same lie as 'nothing found' for a lookup never made."""
    resp = client.post("/case/never-existed/delete", headers=SAME, follow_redirects=False)
    assert resp.status_code == 200
    assert "no longer exists" in resp.text


def test_the_unrecognised_page_has_a_heading_and_a_way_out():
    text = client.get("/q", params={"v": "!!!"}).text
    assert "<h1>Nothing recognised</h1>" in text
    assert 'href="/cases"' in text


def test_a_new_write_route_is_guarded_without_remembering_to_guard_it():
    """Middleware, not a per-route line: applied per route, the fifth POST someone adds arrives unguarded."""
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from casefile.web.app import app

    async def unguarded(request):
        return PlainTextResponse("wrote something")

    route = Route("/probe-new-write", unguarded, methods=["POST"])
    app.router.routes.append(route)
    try:
        assert bare_client.post("/probe-new-write").status_code == 403
        assert client.post("/probe-new-write", headers={"sec-fetch-site": "cross-site"}).status_code == 403
        assert client.post("/probe-new-write", headers=SAME).status_code == 200
    finally:
        app.router.routes.remove(route)


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/star", STAR),
        ("/save", SAVE),
        ("/case/anything/rename", {"name": "x"}),
        ("/case/anything/delete", {}),
    ],
)
def test_every_write_refuses_a_cross_site_request(path, data):
    assert client.post(path, data=data, headers={"sec-fetch-site": "cross-site"}).status_code == 403
