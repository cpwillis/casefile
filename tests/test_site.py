import asyncio
import socket
import ssl

import httpx
import pytest
from helpers import mock_client

from casefile.fetchers import State, run_fetcher, site
from casefile.types import EntityType

PUBLIC = "203.0.113."  # RFC 5737 stands in for a public address: the real check rightly calls it non-global


@pytest.fixture
def dns(monkeypatch):
    """Resolution from a table, never the network; 203.0.113.0/24 is treated as public, everything else is real."""
    table: dict[str, list[str]] = {}

    async def getaddrinfo(self, host, port, *, family=0, type=0, proto=0, flags=0):
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in table[host]
        ]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)
    real = site._public
    monkeypatch.setattr(site, "_public", lambda a: a.startswith(PUBLIC) or real(a))
    return table


def _answer(routes, seen=None):
    def handler(request):
        if seen is not None:
            seen.append(request)
        # Routed by what the server sees, Host plus path: the connection itself goes to the pinned address.
        return routes[f"{request.url.scheme}://{request.headers['host']}{request.url.raw_path.decode()}"]

    return mock_client(handler)


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "192.0.2.10"])
async def test_a_host_resolving_to_a_non_public_address_is_refused(dns, address):
    dns["example.com"] = [address]
    with pytest.raises(site.Refused, match="non-public"):
        await site.checked_address("example.com")


async def test_one_private_address_among_public_ones_still_refuses(dns):
    dns["example.com"] = [PUBLIC + "1", "10.0.0.1"]
    with pytest.raises(site.Refused):
        await site.checked_address("example.com")


async def test_a_refusal_reads_as_a_panel_detail_and_nothing_is_sent(dns):
    dns["example.com"] = ["127.0.0.1"]
    seen = []
    async with _answer({}, seen) as client:
        result = await run_fetcher("site-http", "example.com", EntityType.DOMAIN, client)
    assert result.state == State.ERROR and "non-public" in result.detail
    assert seen == []


PAGE = """<html><head>
<meta property="og:title" content="Example page"><meta name="twitter:card" content="summary">
<meta name="generator" content="WordPress 6.0"></head><body>hi</body></html>"""


async def test_site_http_reports_the_chain_headers_cookies_hints_and_tags(dns, monkeypatch, tmp_path):
    monkeypatch.delenv("CASEFILE_VISIT_USER_AGENT", raising=False)
    monkeypatch.chdir(tmp_path)  # no stray .env supplies a user agent
    dns["example.com"] = dns["www.example.com"] = [PUBLIC + "10"]
    final = httpx.Response(
        200,
        headers=[
            ("content-type", "text/html; charset=utf-8"),
            ("strict-transport-security", "max-age=63072000"),
            ("x-frame-options", "DENY"),
            ("server", "nginx"),
            ("cf-ray", "0000-TEST"),
            ("set-cookie", "PHPSESSID=s3cr3t-token; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ("set-cookie", "pref=other-s3cr3t"),
        ],
        text=PAGE,
    )
    routes = {
        "https://example.com/": httpx.Response(301, headers={"location": "https://www.example.com/"}),
        "https://www.example.com/": final,
    }
    seen = []
    async with _answer(routes, seen) as client:
        findings = await site.site_http("example.com", EntityType.DOMAIN, client)
    got = {(f.label, f.value) for f in findings}
    assert ("status", "200 OK") in got
    assert ("redirect", "301 https://example.com/") in got and ("final URL", "https://www.example.com/") in got
    assert ("security header", "Strict-Transport-Security: max-age=63072000") in got
    assert ("missing header", "Content-Security-Policy") in got
    assert ("cookie", "PHPSESSID: Secure, HttpOnly, SameSite=Lax") in got
    assert ("cookie", "pref: not Secure, not HttpOnly, no SameSite") in got
    assert ("tech hint", "server: nginx") in got and ("tech hint", "Cloudflare (cf-ray header)") in got
    assert ("tech hint", "PHP (PHPSESSID cookie)") in got and ("tech hint", "generator: WordPress 6.0") in got
    assert ("og:title", "Example page") in got and ("twitter:card", "summary") in got
    assert any(f.label == "time to first byte" for f in findings)
    assert not any("s3cr3t" in f.value or "s3cr3t" in f.label for f in findings), "a cookie value leaked"
    assert all(r.headers["user-agent"] == site.CHROME_UA and "accept-language" in r.headers for r in seen)


async def test_the_visit_user_agent_can_be_set(dns, monkeypatch):
    monkeypatch.setenv("CASEFILE_VISIT_USER_AGENT", "Mozilla/5.0 test")
    dns["example.com"] = [PUBLIC + "10"]
    seen = []
    async with _answer({"https://example.com/": httpx.Response(204)}, seen) as client:
        await site.site_http("example.com", EntityType.DOMAIN, client)
    assert seen[0].headers["user-agent"] == "Mozilla/5.0 test"


async def test_a_url_reading_visits_exactly_that_url_and_skips_tags_for_non_html(dns):
    dns["example.com"] = [PUBLIC + "10"]
    url = "https://example.com/a?b=1"
    body = httpx.Response(200, headers={"content-type": "application/json"}, text='{"og:title": 1}')
    async with _answer({url: body}) as client:
        findings = await site.site_http(url, EntityType.URL, client)
    assert ("status", "200 OK") in {(f.label, f.value) for f in findings}
    assert not any(f.label.startswith("og:") for f in findings)


async def test_a_redirect_to_a_private_host_is_refused_before_it_is_contacted(dns):
    dns["example.com"] = [PUBLIC + "10"]
    dns["internal.example"] = ["10.0.0.1"]
    routes = {"https://example.com/": httpx.Response(302, headers={"location": "http://internal.example/admin"})}
    seen = []
    async with _answer(routes, seen) as client:
        with pytest.raises(site.Refused, match="internal.example"):
            await site.site_http("example.com", EntityType.DOMAIN, client)
    assert [r.headers["host"] for r in seen] == ["example.com"]  # internal.example was never sent a request


async def test_redirects_are_capped_at_five(dns):
    dns["example.com"] = [PUBLIC + "10"]
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": f"/{len(seen)}"})

    async with mock_client(handler) as client:
        with pytest.raises(httpx.TooManyRedirects):
            await site.site_http("example.com", EntityType.DOMAIN, client)
    assert len(seen) == 1 + site.MAX_HOPS


async def test_a_visit_leaves_no_cookie_behind_for_the_next_one(dns):
    dns["example.com"] = [PUBLIC + "10"]
    resp = httpx.Response(200, headers={"set-cookie": "sid=abc; Path=/"})
    async with _answer({"https://example.com/": resp}) as client:
        await site.site_http("example.com", EntityType.DOMAIN, client)
        assert len(client.cookies.jar) == 0


ROBOTS = """User-agent: *
Disallow: /admin  # staff only
Disallow: /tmp/
Disallow:
Sitemap: https://example.com/sitemap.xml
"""
SITEMAP = "<urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/a</loc></url></urlset>"
SECURITY = """-----BEGIN PGP SIGNED MESSAGE-----
Contact: mailto:security@example.com
Expires: 2030-01-01T00:00:00.000Z
Policy: https://example.com/policy
Preferred-Languages: en
"""


async def test_site_files_parses_robots_sitemap_and_security_txt(dns):
    dns["example.com"] = [PUBLIC + "10"]
    text = {"content-type": "text/plain"}
    routes = {
        "https://example.com/robots.txt": httpx.Response(200, headers=text, text=ROBOTS),
        "https://example.com/sitemap.xml": httpx.Response(
            200, headers={"content-type": "application/xml"}, text=SITEMAP
        ),
        "https://example.com/.well-known/security.txt": httpx.Response(200, headers=text, text=SECURITY),
    }
    async with _answer(routes) as client:
        findings = await site.site_files("https://example.com/deep/page", EntityType.URL, client)
    got = {(f.label, f.value) for f in findings}
    assert ("robots.txt", "present, 2 disallow rules") in got
    assert ("robots disallow", "/admin") in got and ("robots sitemap", "https://example.com/sitemap.xml") in got
    assert ("sitemap.xml", "present, 2 URLs") in got
    assert ("security.txt", "present, PGP-signed") in got
    assert ("security.txt Contact", "mailto:security@example.com") in got
    assert ("security.txt Preferred-Languages", "en") in got


async def test_missing_files_read_as_absent_not_as_errors(dns):
    dns["example.com"] = [PUBLIC + "10"]
    routes = {
        "https://example.com/robots.txt": httpx.Response(404),
        "https://example.com/sitemap.xml": httpx.Response(410),
        # an app that routes every path to its homepage: a soft 404
        "https://example.com/.well-known/security.txt": httpx.Response(200, headers={"content-type": "text/html"}),
    }
    async with _answer(routes) as client:
        result = await run_fetcher("site-files", "example.com", EntityType.DOMAIN, client)
    assert result.state == State.OK
    assert {(f.label, f.value) for f in result.findings} == {
        ("robots.txt", "absent"),
        ("sitemap.xml", "absent"),
        ("security.txt", "absent"),
    }


class _FakeTLS:
    def __init__(self, cert):
        self.cert = cert

    def getpeercert(self):
        return self.cert

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)


class _FakeWriter:
    def __init__(self, tls):
        self.tls = tls

    def get_extra_info(self, name):
        return self.tls if name == "ssl_object" else None

    def close(self):
        pass

    async def wait_closed(self):
        pass


CERT = {
    "issuer": ((("countryName", "US"),), (("organizationName", "Example CA"),), (("commonName", "Example CA R1"),)),
    "subject": ((("commonName", "example.com"),),),
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2099 GMT",
}


def _connect(monkeypatch, answers):
    calls = []

    async def open_connection(host, port, *, ssl, server_hostname):
        calls.append((host, port, ssl, server_hostname))
        answer = answers[len(calls) - 1]
        if isinstance(answer, Exception):
            raise answer
        return None, _FakeWriter(_FakeTLS(answer))

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    return calls


async def test_site_tls_connects_to_the_checked_address_and_reads_the_leaf(dns, monkeypatch):
    dns["example.com"] = [PUBLIC + "10"]
    calls = _connect(monkeypatch, [CERT])
    findings = await site.site_tls("example.com", EntityType.DOMAIN, None)
    got = {(f.label, f.value) for f in findings}
    assert calls[0][0] == PUBLIC + "10" and calls[0][1] == 443 and calls[0][3] == "example.com"
    assert calls[0][2].verify_mode == ssl.CERT_REQUIRED
    assert ("issuer", "Example CA") in got and ("subject", "example.com") in got
    assert ("SAN", "www.example.com") in got and ("valid until", "Jan  1 00:00:00 2099 GMT") in got
    assert ("protocol", "TLSv1.3") in got and ("cipher", "TLS_AES_128_GCM_SHA256 (128-bit)") in got
    assert int(next(f.value for f in findings if f.label == "days left")) > 0


async def test_an_expired_certificate_is_the_finding_with_protocol_from_an_unverified_retry(dns, monkeypatch):
    dns["example.com"] = [PUBLIC + "10"]
    expired = ssl.SSLCertVerificationError(1, "certificate verify failed")
    expired.verify_message = "certificate has expired"
    calls = _connect(monkeypatch, [expired, {}])
    findings = await site.site_tls("example.com", EntityType.DOMAIN, None)
    got = {(f.label, f.value) for f in findings}
    assert ("verification failed", "certificate has expired") in got
    assert ("protocol", "TLSv1.3") in got and not any(f.label == "issuer" for f in findings)
    assert calls[1][2].verify_mode == ssl.CERT_NONE and calls[1][0] == PUBLIC + "10"


async def test_site_tls_refuses_a_private_host_before_connecting(dns, monkeypatch):
    dns["example.com"] = ["169.254.169.254"]
    calls = _connect(monkeypatch, [CERT])
    result = await run_fetcher("site-tls", "example.com", EntityType.DOMAIN, None)
    assert result.state == State.ERROR and "non-public" in result.detail and calls == []


def test_every_visit_fetcher_contacts_the_target_and_reads_domains_and_urls():
    from casefile.fetchers import registered_fetcher

    for source_id in ("site-http", "site-tls", "site-files"):
        rec = registered_fetcher(source_id)
        assert rec.contacts_target and not rec.on_demand
    assert set(registered_fetcher("site-http").accepts) == {EntityType.DOMAIN, EntityType.URL}
    # Per host: a URL input also yields its domain reading, so on both these would contact the host twice.
    assert set(registered_fetcher("site-tls").accepts) == {EntityType.DOMAIN}
    assert set(registered_fetcher("site-files").accepts) == {EntityType.DOMAIN}


async def test_each_hop_connects_to_the_address_it_checked_with_the_name_in_host_and_sni(dns):
    """DNS must not get a second answer between the check and the connect: the address checked is the one used."""
    dns["example.com"] = [PUBLIC + "10"]
    dns["www.example.com"] = [PUBLIC + "11"]
    seen = []
    routes = {
        "https://example.com/": httpx.Response(301, headers={"location": "https://www.example.com/"}),
        "https://www.example.com/": httpx.Response(200),
    }
    async with _answer(routes, seen) as client:
        findings = await site.site_http("example.com", EntityType.DOMAIN, client)
    assert [r.url.host for r in seen] == [PUBLIC + "10", PUBLIC + "11"]
    assert [r.headers["host"] for r in seen] == ["example.com", "www.example.com"]
    assert [r.extensions["sni_hostname"] for r in seen] == ["example.com", "www.example.com"]
    assert all(r.headers["connection"] == "close" for r in seen)  # no socket reused under another name's SNI
    values = [f.value for f in findings]
    assert "301 https://example.com/" in values and "https://www.example.com/" in values  # names, never addresses
