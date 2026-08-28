import httpx
import pytest

from casefile.fetchers import run_fetcher
from casefile.fetchers.wmn import WMN_ATTRIBUTION, Site, account_exists, check_url, load_sites
from casefile.types import EntityType


def test_dataset_loads_with_many_sites():
    sites = load_sites()
    assert len(sites) > 600


def test_every_site_has_a_usable_check_url():
    for site in load_sites():
        assert "{account}" in site.uri_check, site.name


def test_check_url_substitutes_and_encodes():
    (site,) = [s for s in load_sites() if "{account}" in s.uri_check][:1]
    url = check_url(site, "a b/c")
    assert "{account}" not in url
    assert "a%20b%2Fc" in url


def test_attribution_names_the_project_and_licence():
    assert "WhatsMyName" in WMN_ATTRIBUTION
    assert "CC BY-SA 4.0" in WMN_ATTRIBUTION


def test_protection_flags_are_exposed():
    sites = load_sites()
    assert any(s.protection for s in sites), "the dataset marks captcha/cloudflare sites"


def _site(**kw):
    base = dict(
        name="T",
        uri_check="https://t.test/{account}",
        e_code=200,
        e_string="found-me",
        m_code=404,
        m_string="no-user",
        cat="test",
    )
    base.update(kw)
    return Site(**base)


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, "prefix found-me suffix", True),  # code and string both match
        (200, "nothing here", False),  # right code, wrong body: the classic false positive
        (404, "found-me", False),  # wrong code
        (500, "found-me", False),  # server error is not existence
    ],
)
def test_account_exists_requires_code_and_string(status, body, expected):
    assert account_exists(_site(), status, body) is expected


def test_empty_e_string_falls_back_to_code_and_missing_string():
    site = _site(e_string="", m_string="no-user")
    assert account_exists(site, 200, "whatever") is True
    assert account_exists(site, 200, "no-user here") is False  # missing marker present, so absent
    assert account_exists(site, 404, "whatever") is False


async def test_whatsmyname_reports_only_hits(monkeypatch):
    sites = (
        _site(name="Hit", uri_check="https://hit.test/{account}"),
        _site(name="Miss", uri_check="https://miss.test/{account}"),
    )
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: sites)

    def handler(request):
        if request.url.host == "hit.test":
            return httpx.Response(200, text="found-me")
        return httpx.Response(404, text="no-user")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "someone", EntityType.USERNAME, client)
    assert result.state == "ok"
    assert [f.label for f in result.findings] == ["Hit"]
    assert result.findings[0].url == "https://hit.test/someone"


async def test_whatsmyname_no_hits_is_empty(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: (_site(),))

    def handler(request):
        return httpx.Response(404, text="no-user")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "nobody", EntityType.USERNAME, client)
    assert result.state == "empty"


async def test_whatsmyname_survives_a_dead_site(monkeypatch):
    sites = (
        _site(name="Dead", uri_check="https://dead.test/{account}"),
        _site(name="Alive", uri_check="https://alive.test/{account}"),
    )
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: sites)

    def handler(request):
        if request.url.host == "dead.test":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, text="found-me")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "someone", EntityType.USERNAME, client)
    assert [f.label for f in result.findings] == ["Alive"]


async def test_whatsmyname_survives_a_site_with_an_unparseable_url(monkeypatch):
    """A malformed uri_check must not discard the other sites' findings."""
    sites = (
        _site(name="Bad", uri_check="http://[::1{account}/x"),  # yields an invalid port
        _site(name="Good", uri_check="https://good.test/{account}"),
    )
    monkeypatch.setattr("casefile.fetchers.wmn.load_sites", lambda: sites)

    def handler(request):
        return httpx.Response(200, text="found-me")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_fetcher("whatsmyname", "junk", EntityType.USERNAME, client)
    assert result.state == "ok"
    assert [f.label for f in result.findings] == ["Good"]
