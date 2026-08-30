import httpx
import pytest
from helpers import client as web
from helpers import mock_client, responder

from casefile.catalog import Link
from casefile.linkcheck import BLOCKED, LIVE, MISSING, REDIRECTED, UNREACHABLE, check_link, check_links, tally


@pytest.mark.parametrize(
    ("status", "verdict"),
    [
        # 43 of 78 apparent catalogue failures were bot-protection 403s, so only 404/410 may count as MISSING.
        (200, LIVE),
        (204, LIVE),
        (404, MISSING),
        (410, MISSING),
        (403, BLOCKED),
        (401, BLOCKED),
        (429, BLOCKED),
        (451, BLOCKED),
        (301, REDIRECTED),
        (302, REDIRECTED),
        (500, UNREACHABLE),
    ],
)
async def test_status_maps_to_a_verdict(status, verdict):
    async with responder(status) as client:
        assert await check_link("https://h.test/x", client) == verdict


async def test_a_redirect_is_not_counted_as_live():
    """A site that sends a missing profile home answers 200 after a redirect, so redirects are not followed."""
    seen = {}

    def handler(request):
        seen["followed"] = seen.get("followed", 0) + 1
        return httpx.Response(302, headers={"location": "https://h.test/home"})

    async with mock_client(handler) as client:
        assert await check_link("https://h.test/missing", client) == REDIRECTED
    assert seen["followed"] == 1, "the probe followed the redirect"


async def test_a_probe_that_falls_over_is_a_verdict_not_an_exception():
    def handler(request):
        raise httpx.ConnectError("no route")

    async with mock_client(handler) as client:
        assert await check_link("https://h.test/x", client) == UNREACHABLE


async def test_a_malformed_url_never_raises():
    async with mock_client(responder(200)) as client:
        assert await check_link("not a url", client) == UNREACHABLE


async def test_check_links_returns_one_verdict_per_link_id():
    links = [
        Link(id="a", name="A", url="https://h.test/a"),
        Link(id="b", name="B", url="https://h.test/b"),
    ]

    def handler(request):
        return httpx.Response(404 if request.url.path == "/b" else 200)

    async with mock_client(handler) as client:
        verdicts = await check_links(links, client)
    assert verdicts == {"a": LIVE, "b": MISSING}
    assert tally(verdicts) == {LIVE: 1, MISSING: 1}


def test_the_link_list_offers_the_check_but_never_runs_it_on_page_load(monkeypatch):
    """Egress consent: dozens of third-party requests from your IP are not something a page load does by itself."""
    import casefile.web.app as appmod

    async def explode(links, client):
        raise AssertionError("a page load probed the links")

    monkeypatch.setattr(appmod, "check_links", explode)
    text = web.get("/q", params={"v": "example.com"}).text
    assert "Check for dead links" in text
    assert 'hx-get="/links?v=example.com&amp;t=domain"' in text


def test_the_check_route_renders_verdicts_against_the_links(monkeypatch):
    import casefile.web.app as appmod

    async def fake(links, client):
        return {link.id: (MISSING if link.id == "crtsh" else LIVE) for link in links}

    monkeypatch.setattr(appmod, "check_links", fake)
    text = web.get("/links", params={"v": "example.com", "t": "domain"}).text
    assert 'data-verdict="live"' in text
    assert "nothing here was opened" in text


def test_the_check_route_rejects_an_unknown_type():
    resp = web.get("/links", params={"v": "x", "t": "not-a-type"})
    assert resp.status_code == 200  # rendered so htmx swaps it, like the panel route
    assert "unknown entity type" in resp.text


@pytest.mark.parametrize("header", [None, "", "cross-site", "same-site", "none", "Cross-Site"])
def test_the_check_route_refuses_anything_but_its_own_page(header):
    """One request per link from the user's IP, so the same allowlist the panel route uses. Refused as a rendered
    200 linkset, not a bare 4xx, so htmx swaps it and the button is not left stuck; the check still never runs."""
    from helpers import bare_client

    headers = {} if header is None else {"sec-fetch-site": header}
    resp = bare_client.get("/links", params={"v": "example.com", "t": "domain"}, headers=headers)
    assert resp.status_code == 200
    assert "must come from" in resp.text
    assert 'class="verdict' not in resp.text  # no link was probed
