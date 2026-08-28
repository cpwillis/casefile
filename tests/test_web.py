import inspect

from starlette.testclient import TestClient

from casefile.web.app import app, serve

client = TestClient(app)


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
    assert 'id="type-domain"' in response.text
    assert 'href="#type-domain"' in response.text


def test_result_page_lists_links_with_encoded_values():
    text = client.get("/q", params={"v": "Acme & Co"}).text
    assert "Acme%20%26%20Co" in text


def test_domain_section_precedes_company_section():
    text = client.get("/q", params={"v": "example.com"}).text
    assert text.index('id="type-domain"') < text.index('id="type-company"')


def test_blank_query_falls_back_to_index():
    assert "<form" in client.get("/q", params={"v": "  "}).text


def test_unrecognised_input_says_so():
    assert "nothing recognised" in client.get("/q", params={"v": "!!!"}).text.lower()


def test_query_is_escaped_not_injected():
    payload = "<script>alert(1)</script>"
    text = client.get("/q", params={"v": payload}).text
    assert payload not in text
    assert "&lt;script&gt;" in text
