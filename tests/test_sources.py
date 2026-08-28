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
        return httpx.Response(
            200,
            json={"handle": "EXAMPLE", "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}]},
        )

    async with _client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    assert any(f.label == "registration" for f in findings)


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
