import inspect

from helpers import client

from casefile.web.app import serve


def _panel_block(html: str, source_id: str) -> str:
    """The one panel div that references this source, scanned rather than sliced by offset."""
    marker = html.index(f"/panel/{source_id}")
    start = html.rindex('<div class="panel"', 0, marker)
    end = html.index("</div>", html.index("</div>", start) + 6) + len("</div>")
    return html[start:end]


def test_index_renders_a_search_form():
    response = client.get("/")
    assert response.status_code == 200
    assert "<form" in response.text
    assert 'name="v"' in response.text


def test_search_input_is_labelled():
    text = client.get("/").text
    assert 'for="target"' in text
    assert 'id="target"' in text


def test_index_has_a_heading_and_skip_link():
    text = client.get("/").text
    assert "<h1" in text
    assert 'class="skip"' in text


def test_serve_defaults_to_loopback():
    assert inspect.signature(serve).parameters["host"].default == "127.0.0.1"


def test_result_page_renders_rail_and_pane():
    response = client.get("/q", params={"v": "example.com"})
    assert response.status_code == 200
    assert 'class="rail"' in response.text
    assert 'id="links-domain"' in response.text
    assert 'href="#links-domain"' in response.text


def test_result_page_lists_links_with_encoded_values():
    text = client.get("/q", params={"v": "Acme & Co"}).text
    assert "Acme%20%26%20Co" in text


def test_domain_reading_precedes_company_reading():
    text = client.get("/q", params={"v": "example.com"}).text
    assert text.index('id="links-domain"') < text.index('id="links-company"')


def test_everything_fetched_comes_before_everything_you_must_click():
    """Reading order follows effort: results casefile already has, then the links you go and open yourself."""
    text = client.get("/q", params={"v": "example.com"}).text
    assert text.index('id="results"') < text.index('id="links"')
    assert text.index('class="panels"') < text.index('class="links"')


def test_blank_query_falls_back_to_index():
    assert "<form" in client.get("/q", params={"v": "  "}).text


def test_unrecognised_input_says_so():
    assert "nothing recognised" in client.get("/q", params={"v": "!!!"}).text.lower()


def test_query_is_escaped_not_injected():
    payload = "<script>alert(1)</script>"
    text = client.get("/q", params={"v": payload}).text
    assert payload not in text
    assert "&lt;script&gt;" in text


def test_result_page_emits_self_loading_panels():
    text = client.get("/q", params={"v": "example.com"}).text
    assert 'hx-get="/panel/crtsh?v=example.com&amp;t=domain"' in text
    assert 'hx-trigger="load"' in text


def test_sources_without_a_fetcher_have_no_panel():
    text = client.get("/q", params={"v": "example.com"}).text
    # censys-certs is a link-only catalogue entry, so it must not get a panel div
    assert 'hx-get="/panel/censys-certs' not in text


def test_no_on_demand_source_ever_self_loads():
    """Asserted against the registry: pinned to one source id, a second expensive one could self-load unnoticed."""
    import casefile.fetchers.sources  # noqa: F401
    from casefile.fetchers import _REGISTRY

    on_demand = [r for r in _REGISTRY.values() if r.on_demand]
    assert on_demand, "nothing is on-demand, so this rule is not being checked"
    for rec in on_demand:
        for entity_type in rec.accepts:
            value = {"username": "octocat", "domain": "example.com", "ip": "1.1.1.1"}.get(entity_type.value)
            if value is None:
                continue
            block = _panel_block(client.get("/q", params={"v": value}).text, rec.id)
            assert 'data-state="on-demand"' in block, f"{rec.id} does not ask first"
            assert "hx-trigger" not in block, f"{rec.id} self-loads"


def test_domain_search_does_not_auto_load_the_expensive_checker():
    """example.com reads as a username too, but must not fire hundreds of requests unasked."""
    text = client.get("/q", params={"v": "example.com"}).text
    assert 'hx-get="/panel/whatsmyname' in text
    assert 'hx-trigger="load"' in text  # other panels still self-load
    block = _panel_block(text, "whatsmyname")
    assert "panel-run" in block
    assert 'data-state="on-demand"' in block
    assert "hx-trigger" not in block


def test_cheap_panels_still_self_load():
    block = _panel_block(client.get("/q", params={"v": "example.com"}).text, "dns")
    assert 'hx-trigger="load"' in block


def test_htmx_loads_only_on_the_page_that_swaps():
    """51KB, the largest asset in the wheel, on three pages with no hx- attribute between them."""
    assert "htmx.min.js" in client.get("/q", params={"v": "example.com"}).text
    for path in ("/", "/cases"):
        text = client.get(path).text
        assert "htmx.min.js" not in text, f"{path} loads htmx"
        assert "hx-" not in text, f"{path} grew an hx- attribute and now needs htmx"


def test_free_form_readings_are_folded_when_a_structured_one_exists():
    """On example.com, 35 of 86 links were person/company guesses crowding the one reading that is not a guess."""
    text = client.get("/q", params={"v": "example.com"}).text
    assert '<details class="speculative">' in text
    assert text.count('<details class="speculative">') == 3  # username, person, company
    # folded, not dropped: the links are still in the document
    assert "aleph.occrp.org" in text or text.count('class="links"') == 4


def test_free_form_readings_stay_at_full_weight_when_they_are_all_there_is():
    """A bare word has only free-form readings, so demoting them all would leave the page empty."""
    text = client.get("/q", params={"v": "octocat"}).text
    assert '<details class="speculative">' not in text


def test_static_assets_are_revalidated_rather_than_heuristically_cached():
    """Starlette sends an etag but no cache-control, so a browser guesses a lifetime and serves stale casefile.js."""
    resp = client.get("/static/casefile.js")
    assert resp.headers["cache-control"] == "no-cache"
    assert resp.headers["etag"], "revalidation needs an etag to be cheap"


def test_every_response_refuses_framing():
    # Framed, the page's own htmx panel loads would fetch on behalf of the framing page, from this machine's IP.
    for path in ("/", "/q?v=example.com", "/cases", "/static/casefile.css"):
        assert client.get(path).headers["x-frame-options"] == "DENY"


def test_an_unknown_path_gets_the_styled_not_found_page():
    resp = client.get("/nope")
    assert resp.status_code == 404
    assert "That page does not exist" in resp.text and 'href="/"' in resp.text


def test_a_refused_panel_and_linkset_keep_the_id_the_swap_refocuses():
    assert 'id="linkset-bogus"' in client.get("/links?v=x&t=bogus").text
    assert 'tabindex="-1"' in client.get("/panel/dns?v=example.com&t=bogus").text


def test_a_reload_mid_check_joins_the_running_check_instead_of_offering_to_start_it_again():
    import asyncio

    from casefile import cache
    from casefile.linkcheck import SOURCE_ID

    loop = asyncio.new_event_loop()
    try:  # an unresolved future stands in for a run still going
        cache._IN_FLIGHT[("whatsmyname", "username", "jdoe-example")] = loop.create_future()
        cache._IN_FLIGHT[(SOURCE_ID, "username", "jdoe-example")] = loop.create_future()
        text = client.get("/q", params={"v": "jdoe-example"}).text
    finally:
        cache._IN_FLIGHT.clear()
        loop.close()
    username_links = text.split('id="linkset-username"')[1].split("</ul>")[0]
    assert "Run this check" not in text and "Check for dead links" not in username_links
    assert text.count('hx-trigger="load"') >= 2  # the on-demand panel and the linkset both attach to the live run


def test_a_missing_static_file_is_a_bare_404_not_a_page():
    resp = client.get("/static/nothere.css")
    assert resp.status_code == 404 and "text/html" not in resp.headers["content-type"]


async def test_a_run_interrupted_by_a_restart_is_resumed_on_start():
    """The point of the jobs table: a reloaded page joins the resumed run rather than finding it gone."""
    import asyncio

    from casefile.cache import _job_start, in_flight, pending_jobs
    from casefile.fetchers import Finding, fetcher
    from casefile.types import EntityType
    from casefile.web.app import resume_jobs

    started = []

    @fetcher(id="resume-me", accepts=[EntityType.DOMAIN], on_demand=True)
    async def _f(value, entity_type, client):
        started.append(value)
        return [Finding(label="A", value="1")]

    _job_start(("resume-me", "domain", "example.com"))
    await resume_jobs()
    assert in_flight("resume-me", EntityType.DOMAIN, "example.com")
    await asyncio.sleep(0)
    assert started == ["example.com"]
    assert pending_jobs() == []


async def test_a_job_naming_nothing_resumable_is_dropped_rather_than_retried_on_every_start():
    from casefile.cache import _job_start, pending_jobs
    from casefile.web.app import resume_jobs

    _job_start(("no-such-source", "domain", "example.com"))
    _job_start(("dns", "not-a-type", "example.com"))
    await resume_jobs()
    assert pending_jobs() == []


async def test_a_job_row_for_a_site_visit_is_dropped_not_resumed(monkeypatch):
    """Belt and braces: even a row that should never exist must not make a restart contact the target."""
    from casefile.cache import _job_start, pending_jobs
    from casefile.fetchers import _REGISTRY, Registered
    from casefile.types import EntityType
    from casefile.web.app import resume_jobs

    started = []

    async def _f(value, entity_type, client):
        started.append(value)
        return []

    # setitem, not @fetcher: undone after the test, so no later page grows a fourth visit panel
    rec = Registered("resume-visit", (EntityType.DOMAIN,), _f, contacts_target=True)
    monkeypatch.setitem(_REGISTRY, "resume-visit", rec)
    _job_start(("resume-visit", "domain", "example.com"))
    await resume_jobs()
    assert started == [] and pending_jobs() == []


def test_the_resume_wrapper_is_what_serve_runs_not_the_bare_app():
    """`app` must stay hook-free for importers, so the resume can only ride on what serve hands uvicorn."""
    assert "with_resume(app)" in inspect.getsource(serve)


def test_the_home_page_lists_recent_searches_from_the_cache():
    from casefile.cache import _store
    from casefile.fetchers import SourceResult, State
    from casefile.types import EntityType

    assert "Recent searches" not in client.get("/").text
    _store(SourceResult("dns", State.EMPTY), EntityType.DOMAIN, "example.com")
    text = client.get("/").text
    assert "Recent searches" in text and 'href="/q?v=example.com"' in text


def _visit_block(html: str) -> str:
    start = html.index('<div class="visit">')
    ends = (html.find(marker, start) for marker in ('<h3 class="reading"', "</section>"))
    return html[start : min(e for e in ends if e != -1)]  # up to the next reading's heading


def test_a_domain_renders_one_visit_block_whose_panels_wait_for_its_one_button():
    import casefile.fetchers.site  # noqa: F401 -- registers the visit

    text = client.get("/q", params={"v": "example.com"}).text
    assert text.count('<div class="visit">') == 1 and text.count("Visit the site") == 1
    assert "about 5 requests to <code>example.com</code> from your IP; the" in text
    block = _visit_block(text)
    assert block.count('hx-trigger="visit from:closest .visit"') == 3
    assert 'hx-trigger="load"' not in block and "onclick" not in block
    for source_id in ("site-http", "site-tls", "site-files"):
        assert f"/panel/{source_id}?v=example.com&amp;t=domain" in block


def test_a_url_reading_names_its_host_in_the_visit_note():
    import casefile.fetchers.site  # noqa: F401 -- registers the visit

    text = client.get("/q", params={"v": "https://example.com/a?b=1"}).text
    assert text.count('<div class="visit">') == 2  # the url and the domain it yields: each its own consent
    assert text.count("one request to <code>example.com</code>") == 1  # the url block: that exact page only
    assert text.count("about 5 requests to <code>example.com</code>") == 1  # the domain block: page, TLS, files


def test_a_cached_visit_renders_prefilled_and_the_button_goes_once_nothing_is_left_to_visit():
    import casefile.fetchers.site  # noqa: F401 -- registers the visit
    from casefile.cache import _store
    from casefile.fetchers import Finding, SourceResult, State
    from casefile.types import EntityType

    _store(SourceResult("site-tls", State.OK, (Finding("protocol", "TLSv1.3"),)), EntityType.DOMAIN, "example.com")
    block = _visit_block(client.get("/q", params={"v": "example.com"}).text)
    assert "TLSv1.3" in block and block.count('hx-trigger="visit from:closest .visit"') == 2
    assert "Visit the site" in block
    for source_id in ("site-http", "site-files"):
        _store(SourceResult(source_id, State.EMPTY), EntityType.DOMAIN, "example.com")
    block = _visit_block(client.get("/q", params={"v": "example.com"}).text)
    assert "Visit the site" not in block and "hx-trigger" not in block


def test_a_reload_mid_visit_joins_it_rather_than_asking_again():
    import asyncio

    import casefile.fetchers.site  # noqa: F401 -- registers the visit
    from casefile import cache

    loop = asyncio.new_event_loop()
    try:
        cache._IN_FLIGHT[("site-http", "domain", "example.com")] = loop.create_future()
        block = _visit_block(client.get("/q", params={"v": "example.com"}).text)
    finally:
        cache._IN_FLIGHT.clear()
        loop.close()
    assert block.count('hx-trigger="load"') == 1 and block.count('hx-trigger="visit from:closest .visit"') == 2
