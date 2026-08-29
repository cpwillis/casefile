import inspect

from helpers import client

from casefile.web.app import serve


def _panel_block(html: str, source_id: str) -> str:
    """The single `<div class="panel" ...>` that references this source.

    Parsed by scanning back to the opening div and forward to its close rather than slicing a
    fixed character window, so the test cannot pass or fail because markup moved.
    """
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
    """Reading order follows effort: results casefile already has, then links you go and open.

    Grouping by entity type first put a domain's 49 unvisited links above a username's actual
    findings, so the answers were below the homework.
    """
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


def test_domain_search_does_not_auto_load_the_expensive_checker():
    """example.com reads as a username too, but must not fire hundreds of requests unasked."""
    text = client.get("/q", params={"v": "example.com"}).text
    assert 'hx-get="/panel/whatsmyname' in text  # the panel is offered
    assert 'hx-trigger="load"' in text  # other panels still self-load
    # but the whatsmyname panel specifically must be a button, not a load trigger
    block = _panel_block(text, "whatsmyname")
    assert "panel-run" in block
    assert 'data-state="on-demand"' in block
    assert "hx-trigger" not in block  # the whole point: nothing fires this without a click


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
    """On example.com, 35 of 86 links were person and company guesses competing for the same
    space as the domain, which is the reading that is not a guess."""
    text = client.get("/q", params={"v": "example.com"}).text
    assert '<details class="speculative">' in text
    assert text.count('<details class="speculative">') == 3  # username, person, company
    # folded, not dropped: the links are still in the document
    assert "aleph.occrp.org" in text or text.count('class="links"') == 4


def test_free_form_readings_stay_at_full_weight_when_they_are_all_there_is():
    """A bare word has nothing but free-form readings. Demoting all of them would leave the page
    with nothing on it."""
    text = client.get("/q", params={"v": "octocat"}).text
    assert '<details class="speculative">' not in text
