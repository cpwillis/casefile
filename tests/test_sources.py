import httpx
import pytest
from helpers import mock_client, responder

from casefile.fetchers import Finding, run_fetcher
from casefile.fetchers.sources import (  # noqa: F401 -- import registers them
    blockscout_tx,
    crtsh,
    dns,
    github,
    hashlookup,
    internetdb,
    malwarebazaar,
    mempool_address,
    mempool_tx,
    nvd_cve,
    phone_meta,
    rdap,
    wikidata,
)
from casefile.types import EntityType


async def test_dns_parses_answer_records():
    def handler(request):
        assert "example.com" in str(request.url)
        return httpx.Response(200, json={"Answer": [{"type": 1, "data": "192.0.2.10"}, {"type": 15, "data": "0 ."}]})

    async with mock_client(handler) as client:
        findings = await dns("example.com", EntityType.DOMAIN, client)
    assert Finding(label="A", value="192.0.2.10") in findings


async def test_dns_of_an_email_uses_the_domain_part():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"Answer": []})

    async with mock_client(handler) as client:
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

    async with mock_client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    assert any(f.label == "registration" for f in findings)


async def test_rdap_asn_strips_the_as_prefix():
    def handler(request):
        assert str(request.url) == "https://rdap.org/autnum/64496"
        return httpx.Response(200, json={})

    async with mock_client(handler) as client:
        await rdap("AS64496", EntityType.ASN, client)


async def test_rdap_ip_uses_the_ip_path():
    def handler(request):
        assert str(request.url) == "https://rdap.org/ip/192.0.2.10"
        return httpx.Response(200, json={})

    async with mock_client(handler) as client:
        await rdap("192.0.2.10", EntityType.IP, client)


async def test_crtsh_dedupes_names():
    def handler(request):
        return httpx.Response(
            200,
            json=[{"name_value": "a.example.com\nexample.com"}, {"name_value": "a.example.com"}],
        )

    async with mock_client(handler) as client:
        findings = await crtsh("example.com", EntityType.DOMAIN, client)
    values = sorted(f.value for f in findings)
    assert values == ["a.example.com", "example.com"]


async def test_empty_answer_becomes_empty_state():
    async with responder(200, json={"Answer": []}) as client:
        r = await run_fetcher("dns", "example.com", EntityType.DOMAIN, client)
    assert r.state == "empty"


async def test_dns_value_cannot_inject_an_extra_type_param():
    """A value containing '&type=ANY' must land inside the name param, not add a second type."""
    seen = []

    def handler(request):
        seen.append(request.url)
        return httpx.Response(200, json={"Answer": []})

    async with mock_client(handler) as client:
        await dns("example.com&type=ANY&x=evil", EntityType.DOMAIN, client)
    assert seen  # dns() fans out over 5 record types; each call must be clean
    for url in seen:
        assert url.params.get_list("name") == ["example.com&type=ANY&x=evil"]
        assert len(url.params.get_list("type")) == 1
    types_seen = {url.params["type"] for url in seen}
    assert types_seen == {"A", "AAAA", "MX", "TXT", "NS"}  # casefile's own types, untouched


async def test_crtsh_value_cannot_inject_an_extra_output_param():
    """A value containing '&output=html' must not make crt.sh answer with HTML instead of JSON."""
    seen = {}

    def handler(request):
        seen["url"] = request.url
        return httpx.Response(200, json=[])

    async with mock_client(handler) as client:
        await crtsh("example.com&output=html", EntityType.DOMAIN, client)
    url = seen["url"]
    assert url.params.get_list("q") == ["example.com&output=html"]
    assert url.params.get_list("output") == ["json"]


async def test_rdap_value_cannot_traverse_the_path_or_add_a_query():
    """A value containing '../' and '?' must stay inside one encoded path segment."""
    seen = {}

    def handler(request):
        seen["url"] = request.url
        return httpx.Response(200, json={})

    async with mock_client(handler) as client:
        await rdap("../../secret?x=1", EntityType.DOMAIN, client)
    url = seen["url"]
    assert url.host == "rdap.org"
    assert url.params == httpx.QueryParams()
    # url.path is decoded; raw_path is what goes on the wire, which is what decides whether '/' and '?' stayed literal.
    segment = url.raw_path.removeprefix(b"/domain/")
    assert b"/" not in segment
    assert b"?" not in segment
    from urllib.parse import unquote

    assert unquote(segment.decode()) == "../../secret?x=1"


async def test_internetdb_lists_ports_and_hostnames():
    def handler(request):
        assert request.url.path == "/8.8.8.8"
        return httpx.Response(
            200,
            json={"ip": "8.8.8.8", "ports": [80, 443], "hostnames": ["a.example.com"], "tags": ["cdn"], "vulns": []},
        )

    async with mock_client(handler) as client:
        findings = await internetdb("8.8.8.8", EntityType.IP, client)
    labels = {f.label for f in findings}
    assert "port" in labels
    assert Finding(label="hostname", value="a.example.com") in findings


async def test_internetdb_404_is_empty_not_error():
    async with responder(404, json={"detail": "No information available"}) as client:
        result = await run_fetcher("internetdb", "8.8.8.8", EntityType.IP, client)
    assert result.state == "empty"


@pytest.mark.parametrize("addr", ["10.0.0.1", "100.64.0.1", "fc00::1", "192.0.2.10", "169.254.1.1"])
async def test_internetdb_never_queries_a_non_global_address(addr):
    """Verified live: 10.0.0.1 answers 200 with junk (ports: [161]), so the guard prevents a wrong answer, not waste."""

    def handler(request):
        raise AssertionError("no request should be made for a non-global address")

    async with mock_client(handler) as client:
        result = await run_fetcher("internetdb", addr, EntityType.IP, client)
    # Skipped, not "empty": empty would claim InternetDB answered and had nothing about a host it never saw.
    assert result.state == "ok"
    (note,) = result.findings
    assert note.label == "note"
    assert "not queried" in note.value


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

    async with mock_client(handler) as client:
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

    async with mock_client(handler) as client:
        findings = await github("octocat", EntityType.USERNAME, client)
    values = {f.label: f.value for f in findings}
    assert values["name"] == "The Octocat"
    assert values["company"] == "GitHub"
    assert "blog" not in values  # empty fields are omitted, not shown blank


async def test_github_404_is_empty_not_error():
    async with responder(404, json={"message": "Not Found"}) as client:
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

    async with mock_client(handler) as client:
        findings = await wikidata("Cloudflare", EntityType.COMPANY, client)
    assert findings[0].label == "Cloudflare"
    assert "internet infrastructure" in findings[0].value
    assert findings[0].url == "https://www.wikidata.org/wiki/Q4778915"


async def test_wikidata_no_matches_is_empty():
    async with responder(200, json={"search": []}) as client:
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

    async with mock_client(handler) as client:
        findings = await hashlookup("d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH, client)
    labels = {f.label: f.value for f in findings}
    assert labels["known good file"] == "requires.txt"
    assert labels["product"] == "Photoshop"


async def test_hashlookup_unknown_hash_is_empty():
    async with responder(404, json={"message": "Non existing MD5"}) as client:
        result = await run_fetcher("hashlookup", "0" * 32, EntityType.HASH, client)
    assert result.state == "empty"


async def test_hashlookup_picks_the_endpoint_by_hash_length():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        return httpx.Response(404, json={"message": "nope"})

    async with mock_client(handler) as client:
        await hashlookup("a" * 40, EntityType.HASH, client)
    assert "sha1" in seen["path"]


async def test_malwarebazaar_without_a_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: None)

    def handler(request):
        raise AssertionError("no request should be made without a key")

    async with mock_client(handler) as client:
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

    async with mock_client(handler) as client:
        findings = await malwarebazaar("a" * 64, EntityType.HASH, client)
    assert seen["auth"] == "secret"
    assert "query=get_info" in seen["body"]
    labels = {f.label: f.value for f in findings}
    assert labels["signature"] == "AgentTesla"
    assert labels["file"] == "evil.exe"


async def test_malwarebazaar_hash_not_found_is_empty(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "secret")

    async with responder(200, json={"query_status": "hash_not_found"}) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "empty"


async def test_malwarebazaar_rejected_key_is_needs_key(monkeypatch):
    monkeypatch.setattr("casefile.fetchers.sources.get_key", lambda name: "bad")

    async with responder(200, json={"error": "Unauthorized"}) as client:
        result = await run_fetcher("malwarebazaar", "a" * 64, EntityType.HASH, client)
    assert result.state == "needs_key"


async def test_phone_meta_reports_region_and_formats():
    findings = await phone_meta("+61255500000", EntityType.PHONE, client=None)
    labels = {f.label: f.value for f in findings}
    assert labels["region"] == "AU"
    assert labels["location"] == "Australia"
    assert labels["E.164"] == "+61255500000"
    assert labels["international"] == "+61 2 5550 0000"
    assert labels["well formed"] == "yes"


async def test_phone_meta_makes_no_network_call():
    def handler(request):
        raise AssertionError("phone_meta must be offline")

    async with mock_client(handler) as client:
        findings = await phone_meta("+14155550100", EntityType.PHONE, client)
    assert any(f.label == "location" for f in findings)


async def test_phone_meta_distinguishes_no_country_code_from_unparseable():
    """Both raise INVALID_COUNTRY_CODE, so the branch keys off the missing + rather than the library's prose."""
    (note,) = await phone_meta("0255500000", EntityType.PHONE, client=None)
    assert note.label == "note"
    assert "country code" in note.value
    assert await phone_meta("+999", EntityType.PHONE, client=None) == []


async def test_dns_servfail_is_an_error_not_an_empty_answer():
    """DoH answers 200 for SERVFAIL, so reading only the Answer section caches a resolver failure as no records."""

    async with responder(200, json={"Status": 2, "Comment": ["EDE(9): DNSKEY Missing"]}) as client:
        result = await run_fetcher("dns", "broken.example", EntityType.DOMAIN, client)
    assert result.state == "error"
    assert "SERVFAIL" in result.detail


async def test_dns_nxdomain_is_reported_as_a_finding_not_as_silence():
    """NXDOMAIN is a positive result, distinct from existing with none of the record types asked for."""

    async with responder(200, json={"Status": 3}) as client:
        result = await run_fetcher("dns", "nope.example", EntityType.DOMAIN, client)
    assert result.state == "ok"
    (note,) = result.findings
    assert "NXDOMAIN" in note.value


async def test_dns_no_records_of_these_types_stays_empty():
    """The third case, which must not be confused with either of the two above."""

    async with responder(200, json={"Status": 0}) as client:
        result = await run_fetcher("dns", "bare.example", EntityType.DOMAIN, client)
    assert result.state == "empty"


async def test_rdap_surfaces_ownership_netblock_and_delegation():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "handle": "EXAMPLE-NET",
                "name": "EXAMPLE-BLOCK",
                "country": "AU",
                "startAddress": "192.0.2.0",
                "endAddress": "192.0.2.255",
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "ns2.example.com"}],
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Pty"]]],
                    }
                ],
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}],
            },
        )

    async with mock_client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    got = {f.label: f.value for f in findings}
    assert got["name"] == "EXAMPLE-BLOCK"
    assert got["country"] == "AU"
    assert got["range"] == "192.0.2.0 - 192.0.2.255"
    assert got["registrant"] == "Acme Pty"
    assert got["registration"] == "1995-08-14"
    assert {f.value for f in findings if f.label == "nameserver"} == {"ns1.example.com", "ns2.example.com"}


async def test_rdap_survives_a_malformed_vcard():
    """jCard is a nested array rather than an object, so the shape has to be checked rather than trusted."""

    def handler(request):
        return httpx.Response(
            200,
            json={
                "handle": "X",
                "entities": [
                    {"roles": ["registrant"], "vcardArray": "not-an-array"},
                    {"roles": ["tech"], "vcardArray": ["vcard", [["fn"]]]},
                    "not-a-dict",
                ],
            },
        )

    async with mock_client(handler) as client:
        findings = await rdap("example.com", EntityType.DOMAIN, client)
    assert [f.label for f in findings] == ["handle"]


async def test_rdap_asn_reports_its_range():
    async with responder(200, json={"startAutnum": 64496, "endAutnum": 64511, "name": "EXAMPLE-AS"}) as client:
        findings = await rdap("AS64496", EntityType.ASN, client)
    assert {f.label: f.value for f in findings}["as range"] == "AS64496 - AS64511"


async def test_crtsh_caps_its_output_and_says_that_it_did():
    """The note is the load-bearing half: a silent slice would report 500 names as if that were all there is."""

    def handler(request):
        names = "\n".join(f"sub{i}.example.com" for i in range(20000))
        return httpx.Response(200, json=[{"name_value": names}])

    async with mock_client(handler) as client:
        findings = await crtsh("example.com", EntityType.DOMAIN, client)
    assert len(findings) == 501
    assert findings[0].label == "note"
    assert "20000 names found" in findings[0].value


async def test_crtsh_adds_no_note_when_nothing_was_cut():
    async with responder(200, json=[{"name_value": "a.example.com\nb.example.com"}]) as client:
        findings = await crtsh("example.com", EntityType.DOMAIN, client)
    assert [f.label for f in findings] == ["subdomain", "subdomain"]


async def test_nvd_reads_an_unassigned_cve_off_the_body_not_the_status():
    """NVD answers 200 with an empty result set for an unassigned id, so status alone reports it as an error."""

    async with responder(200, json={"totalResults": 0, "vulnerabilities": []}) as client:
        result = await run_fetcher("nvd-cve", "CVE-1999-99999", EntityType.CVE, client)
    assert result.state == "empty"


async def test_nvd_takes_the_newest_cvss_generation_present():
    """Four CVSS generations are live in NVD at once, so a reader hardcoded to V31 shows nothing on new CVEs."""

    def handler(request):
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "descriptions": [{"lang": "en", "value": "a flaw"}],
                            "metrics": {
                                "cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
                                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
                            },
                        }
                    }
                ]
            },
        )

    async with mock_client(handler) as client:
        findings = await nvd_cve("CVE-2026-1", EntityType.CVE, client)
    assert {f.label: f.value for f in findings}["severity"] == "9.3 CRITICAL"


async def test_mempool_tx_does_not_parse_a_text_plain_miss_as_json():
    """404 and 400 come back as text/plain, so touching json() before the status turns a miss into a decode error."""

    async with responder(404, text="Transaction not found") as client:
        result = await run_fetcher("mempool-space-tx", "0" * 64, EntityType.TX_HASH, client)
    assert result.state == "empty"
    assert result.detail is None


async def test_mempool_tx_reads_an_unconfirmed_transaction_without_block_keys():
    """While a transaction is unconfirmed the block_* keys are absent entirely, not null."""

    async with responder(200, json={"status": {"confirmed": False}, "fee": 1040, "vin": [{}], "vout": []}) as client:
        findings = await mempool_tx("a" * 64, EntityType.TX_HASH, client)
    got = {f.label: f.value for f in findings}
    assert got["confirmed"].startswith("no")
    assert "block height" not in got


async def test_an_unused_bitcoin_address_says_unused_rather_than_not_found():
    """There is no 404 for an address: rendering zero activity as nothing-found implies it is unknown, not unused."""

    def handler(request):
        return httpx.Response(
            200,
            json={
                "chain_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 0},
                "mempool_stats": {"tx_count": 0},
            },
        )

    async with mock_client(handler) as client:
        result = await run_fetcher("mempool-space-btc", "1" + "A" * 33, EntityType.BTC_ADDRESS, client)
    assert result.state == "ok"
    (note,) = result.findings
    assert "no on-chain activity" in note.value


async def test_a_bitcoin_address_balance_is_received_minus_sent():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "chain_stats": {"funded_txo_sum": 500, "spent_txo_sum": 200, "tx_count": 3},
                "mempool_stats": {"tx_count": 0},
            },
        )

    async with mock_client(handler) as client:
        findings = await mempool_address("1" + "A" * 33, EntityType.BTC_ADDRESS, client)
    assert {f.label: f.value for f in findings}["balance"].startswith("300 sats")


@pytest.mark.parametrize(
    ("wei", "expected"),
    [
        (10**18, "1 ETH"),
        (10**17, "0.1 ETH"),
        (33 * 10**17, "3.3 ETH"),
        (1234567890123456789, "1.234567890123456789 ETH"),
        (0, "0 ETH"),
        (1, "0.000000000000000001 ETH"),
    ],
)
async def test_an_ethereum_value_is_exact(wei, expected):
    """18 decimals does not survive a float: 0.1 rendered as 0.100000000000000006."""

    async with responder(200, json={"value": str(wei), "result": "success"}) as client:
        findings = await blockscout_tx("a" * 64, EntityType.TX_HASH, client)
    assert {f.label: f.value for f in findings}["value"] == expected


@pytest.mark.parametrize("status", [404, 422])
async def test_blockscout_miss_is_empty_not_error(status):
    """404 is no such transaction, 422 a malformed hash, and a Bitcoin hash on the Ethereum panel hits 422 often."""
    async with responder(status, json={"message": "Not found"}) as client:
        result = await run_fetcher("blockscout-tx", "b" * 64, EntityType.TX_HASH, client)
    assert result.state == "empty"
    assert result.detail is None


async def test_blockscout_reads_the_nested_from_and_to_objects():
    payload = {
        "result": "success",
        "block_number": 46147,
        "from": {"hash": "0xAAA"},
        "to": {"hash": "0xBBB"},
        "value": "31337",
    }
    async with responder(200, json=payload) as client:
        got = {f.label: f.value for f in await blockscout_tx("c" * 64, EntityType.TX_HASH, client)}
    assert got["from"] == "0xAAA"
    assert got["to"] == "0xBBB"
    assert got["block"] == "46147"
