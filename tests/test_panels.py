from starlette.testclient import TestClient

import casefile.fetchers.sources  # noqa: F401 -- register the real fetchers
from casefile.fetchers import fetchers_for
from casefile.types import EntityType
from casefile.web.app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_domain_has_the_three_fetchers_registered():
    ids = [r.id for r in fetchers_for(EntityType.DOMAIN)]
    assert {"dns", "rdap", "crtsh"} <= set(ids)


def test_panel_route_renders_a_state(monkeypatch):
    from casefile.fetchers import Finding, SourceResult, State

    async def fake_run(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="A", value="192.0.2.10"),))

    monkeypatch.setattr("casefile.web.app.run_cached", fake_run)
    resp = client.get("/panel/dns", params={"v": "example.com", "t": "domain"})
    assert resp.status_code == 200
    assert "192.0.2.10" in resp.text
    assert 'data-state="ok"' in resp.text


def test_panel_empty_and_error_render_differently(monkeypatch):
    from casefile.fetchers import SourceResult, State

    async def fake(source_id, value, entity_type, client):
        state = State.EMPTY if source_id == "e" else State.ERROR
        return SourceResult(source_id, state, detail=None if state == State.EMPTY else "boom")

    monkeypatch.setattr("casefile.web.app.run_cached", fake)
    empty = client.get("/panel/e", params={"v": "example.com", "t": "domain"}).text
    error = client.get("/panel/x", params={"v": "example.com", "t": "domain"}).text
    assert 'data-state="empty"' in empty
    assert 'data-state="error"' in error
    assert "boom" in error


def test_panel_escapes_untrusted_findings(monkeypatch):
    from casefile.fetchers import Finding, SourceResult, State

    async def fake(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="x", value="<script>alert(1)</script>"),))

    monkeypatch.setattr("casefile.web.app.run_cached", fake)
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
    from casefile.fetchers import Finding, SourceResult, State

    async def fake(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="x", value="click me", url="javascript:alert(1)"),))

    monkeypatch.setattr("casefile.web.app.run_cached", fake)
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'href="javascript:' not in text
    assert "click me" in text


def test_panel_still_links_an_http_url(monkeypatch):
    from casefile.fetchers import Finding, SourceResult, State

    async def fake(source_id, value, entity_type, client):
        return SourceResult(
            source_id, State.OK, (Finding(label="x", value="sub.example.com", url="https://sub.example.com"),)
        )

    monkeypatch.setattr("casefile.web.app.run_cached", fake)
    text = client.get("/panel/dns", params={"v": "example.com", "t": "domain"}).text
    assert 'href="https://sub.example.com"' in text


def test_whatsmyname_panel_renders_the_required_attribution(monkeypatch):
    """CC BY-SA requires attribution where the material is used, so the UI must carry it."""
    from casefile.fetchers import Finding, SourceResult, State

    async def fake(source_id, value, entity_type, client):
        return SourceResult(source_id, State.OK, (Finding(label="Hit", value="tech", url="https://h.test/x"),))

    monkeypatch.setattr("casefile.web.app.run_cached", fake)
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
