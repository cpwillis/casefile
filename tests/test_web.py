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
