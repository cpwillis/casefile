import httpx

from casefile.fetchers import Finding, run_fetcher
from casefile.fetchers.sources import (  # noqa: F401 -- import registers them
    crtsh,
    dns,
    github,
    hashlookup,
    internetdb,
    malwarebazaar,
    rdap,
    wikidata,
)
from casefile.types import EntityType


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_dns_parses_answer_records():
    def handler(request):
        assert "example.com" in str(request.url)
        return httpx.Response(200, json={"Answer": [{"type": 1, "data": "192.0.2.10"}, {"type": 15, "data": "0 ."}]})

    async with _client(handler) as client:
        findings = await dns("example.com", EntityType.DOMAIN, client)
    assert Finding(label="A", value="192.0.2.10") in findings


async def test_dns_of_an_email_uses_the_domain_part():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"Answer": []})

    async with _client(handler) as client:
        await dns("user@example.com", EntityType.EMAIL, client)
    assert "example.com" in seen["url"]
    assert "user" not in seen["url"].split("name=")[1]


async def test_rdap_pulls_registration_fields():
    def handler(request):
        assert str(request.url) == "https://rdap.org/domain/example.com"
        return httpx.Response(
            200,
            json={"handle": "EXAMPLE", "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}]},
        )

    async with _client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    assert any(f.label == "registration" for f in findings)


async def test_rdap_asn_strips_the_as_prefix():
    def handler(request):
        assert str(request.url) == "https://rdap.org/autnum/64496"
        return httpx.Response(200, json={})

    async with _client(handler) as client:
        await rdap("AS64496", EntityType.ASN, client)


async def test_rdap_ip_uses_the_ip_path():
    def handler(request):
        assert str(request.url) == "https://rdap.org/ip/192.0.2.10"
        return httpx.Response(200, json={})

    async with _client(handler) as client:
        await rdap("192.0.2.10", EntityType.IP, client)


async def test_crtsh_dedupes_names():
    def handler(request):
        return httpx.Response(
            200,
            json=[{"name_value": "a.example.com\nexample.com"}, {"name_value": "a.example.com"}],
        )

    async with _client(handler) as client:
        findings = await crtsh("example.com", EntityType.DOMAIN, client)
    values = sorted(f.value for f in findings)
    assert values == ["a.example.com", "example.com"]


async def test_empty_answer_becomes_empty_state():
    def handler(request):
        return httpx.Response(200, json={"Answer": []})

    async with _client(handler) as client:
        r = await run_fetcher("dns", "example.com", EntityType.DOMAIN, client)
    assert r.state == "empty"


async def test_dns_value_cannot_inject_an_extra_type_param():
    """A value containing '&type=ANY' must land inside the name param, not add a second type."""
    seen = []

    def handler(request):
        seen.append(request.url)
        return httpx.Response(200, json={"Answer": []})

    async with _client(handler) as client:
        await dns("example.com&type=ANY&x=evil", EntityType.DOMAIN, client)
    assert seen  # dns() fans out over 5 record types; each call must be clean
    for url in seen:
        assert url.params.get_list("name") == ["example.com&type=ANY&x=evil"]
        assert len(url.params.get_list("type")) == 1  # never two, however the value is crafted
    types_seen = {url.params["type"] for url in seen}
    assert types_seen == {"A", "AAAA", "MX", "TXT", "NS"}  # casefile's own types, untouched


async def test_crtsh_value_cannot_inject_an_extra_output_param():
    """A value containing '&output=html' must not make crt.sh answer with HTML instead of JSON."""
    seen = {}

    def handler(request):
        seen["url"] = request.url
        return httpx.Response(200, json=[])

    async with _client(handler) as client:
        await crtsh("example.com&output=html", EntityType.DOMAIN, client)
    url = seen["url"]
    assert url.params.get_list("q") == ["example.com&output=html"]
    assert url.params.get_list("output") == ["json"]  # exactly one, and it's ours


async def test_rdap_value_cannot_traverse_the_path_or_add_a_query():
    """A value containing '../' and '?' must stay inside one encoded path segment."""
    seen = {}

    def handler(request):
        seen["url"] = request.url
        return httpx.Response(200, json={})

    async with _client(handler) as client:
        await rdap("../../secret?x=1", EntityType.DOMAIN, client)
    url = seen["url"]
    assert url.host == "rdap.org"
    assert url.params == httpx.QueryParams()  # no query injected
    # url.path is decoded back to its logical form; raw_path is what's actually sent on the
    # wire, which is what matters for whether '/' and '?' stayed literal (ie exploitable).
    segment = url.raw_path.removeprefix(b"/domain/")
    assert b"/" not in segment  # no extra path segments introduced on the wire
    assert b"?" not in segment  # no query separator smuggled into the path
    from urllib.parse import unquote

    assert unquote(segment.decode()) == "../../secret?x=1"  # the raw value round-trips out


async def test_internetdb_lists_ports_and_hostnames():
    def handler(request):
        assert request.url.path == "/8.8.8.8"
        return httpx.Response(
            200,
            json={"ip": "8.8.8.8", "ports": [80, 443], "hostnames": ["a.example.com"], "tags": ["cdn"], "vulns": []},
        )

    async with _client(handler) as client:
        findings = await internetdb("8.8.8.8", EntityType.IP, client)
    labels = {f.label for f in findings}
    assert "port" in labels
    assert Finding(label="hostname", value="a.example.com") in findings


async def test_internetdb_404_is_empty_not_error():
    def handler(request):
        return httpx.Response(404, json={"detail": "No information available"})

    async with _client(handler) as client:
        result = await run_fetcher("internetdb", "8.8.8.8", EntityType.IP, client)
    assert result.state == "empty"


async def test_internetdb_skips_private_addresses_without_a_request():
    """Verified live: 10.0.0.1 returns 200 with junk (ports:[161]), so never ask about internal IPs."""

    def handler(request):
        raise AssertionError("no request should be made for a private address")

    async with _client(handler) as client:
        result = await run_fetcher("internetdb", "10.0.0.1", EntityType.IP, client)
    assert result.state == "empty"


async def test_internetdb_skips_non_global_addresses_of_both_families():
    """CGNAT and IPv6 private space are not RFC1918 but must still never be queried."""

    def handler(request):
        raise AssertionError("no request should be made for a non-global address")

    for addr in ("100.64.0.1", "fc00::1", "192.0.2.10", "169.254.1.1"):
        async with _client(handler) as client:
            result = await run_fetcher("internetdb", addr, EntityType.IP, client)
        assert result.state == "empty", addr


async def test_internetdb_surfaces_cpes_and_vulns():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "ports": [],
                "hostnames": [],
                "cpes": ["cpe:/a:cloudflare:cloudflare"],
                "tags": [],
                "vulns": ["CVE-2021-40438"],
            },
        )

    async with _client(handler) as client:
        findings = await internetdb("8.8.8.8", EntityType.IP, client)
    labels = {f.label for f in findings}
    assert {"cpe", "vuln"} <= labels
    vuln = next(f for f in findings if f.label == "vuln")
    assert vuln.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"


async def test_github_surfaces_profile_fields():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "login": "octocat",
                "name": "The Octocat",
                "company": "GitHub",
                "location": "SF",
                "public_repos": 8,
                "created_at": "2011-01-25T18:44:36Z",
                "html_url": "https://github.com/octocat",
                "blog": "",
            },
        )

    async with _client(handler) as client:
        findings = await github("octocat", EntityType.USERNAME, client)
    values = {f.label: f.value for f in findings}
    assert values["name"] == "The Octocat"
    assert values["company"] == "GitHub"
    assert "blog" not in values  # empty fields are omitted, not shown blank


async def test_github_404_is_empty_not_error():
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    async with _client(handler) as client:
        result = await run_fetcher("github", "nope", EntityType.USERNAME, client)
    assert result.state == "empty"


async def test_wikidata_returns_entity_matches():
    def handler(request):
        assert request.url.params["action"] == "wbsearchentities"
        return httpx.Response(
            200,
            json={
                "search": [
                    {
                        "id": "Q4778915",
                        "label": "Cloudflare",
                        "description": "American internet infrastructure company",
                        "concepturi": "http://www.wikidata.org/entity/Q4778915",
                    }
                ]
            },
        )

    async with _client(handler) as client:
        findings = await wikidata("Cloudflare", EntityType.COMPANY, client)
    assert findings[0].label == "Cloudflare"
    assert "internet infrastructure" in findings[0].value
    assert findings[0].url == "https://www.wikidata.org/wiki/Q4778915"


async def test_wikidata_no_matches_is_empty():
    def handler(request):
        return httpx.Response(200, json={"search": []})

    async with _client(handler) as client:
        result = await run_fetcher("wikidata", "zzzz", EntityType.COMPANY, client)
    assert result.state == "empty"


async def test_hashlookup_reports_a_known_file():
    def handler(request):
        assert request.url.path.startswith("/lookup/md5/")
        return httpx.Response(
            200,
            json={
                "FileName": "requires.txt",
                "FileSize": "0",
                "MD5": "D41D8CD9",
                "ProductCode": {"ProductName": "Photoshop"},
            },
        )

    async with _client(handler) as client:
        findings = await hashlookup("d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH, client)
    labels = {f.label: f.value for f in findings}
    assert labels["known file"] == "requires.txt"
    assert labels["product"] == "Photoshop"


async def test_hashlookup_unknown_hash_is_empty():
    def handler(request):
        return httpx.Response(404, json={"message": "Non existing MD5"})

    async with _client(handler) as client:
        result = await run_fetcher("hashlookup", "0" * 32, EntityType.HASH, client)
    assert result.state == "empty"


async def test_hashlookup_picks_the_endpoint_by_hash_length():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        return httpx.Response(404, json={"message": "nope"})

    async with _client(handler) as client:
        await hashlookup("a" * 40, EntityType.HASH, client)
    assert "sha1" in seen["path"]


async def test_malwarebazaar_without_a_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: None)

    def handler(request):  # must never be called
        raise AssertionError("no request should be made without a key")

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "needs_key"
    assert "ABUSECH_AUTH_KEY" in result.detail


async def test_malwarebazaar_with_a_key_posts_and_parses(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "secret")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("auth-key")
        seen["body"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "file_name": "evil.exe",
                        "file_type": "exe",
                        "signature": "AgentTesla",
                        "first_seen": "2026-01-01",
                        "tags": ["exe", "trojan"],
                    }
                ],
            },
        )

    async with _client(handler) as client:
        findings = await malwarebazaar("a" * 64, EntityType.HASH, client)
    assert seen["auth"] == "secret"
    assert "query=get_info" in seen["body"]
    labels = {f.label: f.value for f in findings}
    assert labels["signature"] == "AgentTesla"
    assert labels["file"] == "evil.exe"


async def test_malwarebazaar_hash_not_found_is_empty(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "secret")

    def handler(request):
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "empty"


async def test_malwarebazaar_rejected_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "bad")

    def handler(request):
        return httpx.Response(200, json={"error": "Unauthorized"})

    async with _client(handler) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "needs_key"
