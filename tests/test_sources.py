import httpx

from casefile.fetchers import Finding, run_fetcher
from casefile.fetchers.sources import crtsh, dns, rdap  # noqa: F401 -- import registers them
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
