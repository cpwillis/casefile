"""The site visit: the only fetchers that contact the target itself. Run on a click or --visit, never on their own."""

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from contextlib import suppress
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx

from casefile.config import get_key
from casefile.fetchers import Finding, _reason, fetcher, http
from casefile.types import EntityType

# ponytail: a pinned string ages; CASEFILE_VISIT_USER_AGENT overrides it, bump on a release that touches this file.
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36"
)
MAX_HOPS = 5
TLS_TIMEOUT = 15.0
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-vercel-id": "Vercel",
    "x-served-by": "Fastly or Varnish",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "akamai-grn": "Akamai",
}
COOKIE_HINTS = {
    "phpsessid": "PHP",
    "jsessionid": "Java servlet",
    "wordpress_": "WordPress",
    "laravel_session": "Laravel",
    "asp.net_sessionid": "ASP.NET",
}
_VALUE_CAP = 200  # a CSP can run to kilobytes; the panel needs its shape, not every source


class Refused(Exception):
    """A hop that would reach a non-public address, refused before any packet goes to it."""


def visit_headers() -> dict[str, str]:
    """Per request, visits only: third-party APIs keep the casefile UA, which names the tool on purpose."""
    return {
        "user-agent": get_key("CASEFILE_VISIT_USER_AGENT") or CHROME_UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
    }


def host_of(value: str, entity_type: EntityType) -> str:
    return (urlsplit(value).hostname or "") if entity_type is EntityType.URL else value


def _public(address: str) -> bool:
    return ipaddress.ip_address(address.split("%")[0]).is_global  # %: an IPv6 scope id


async def checked_address(host: str) -> str:
    """Resolve host and refuse unless every address is global; returns one checked address to connect to."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise Refused(f"{host} does not resolve") from exc
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise Refused(f"{host} does not resolve")
    for address in addresses:
        if not _public(address):
            raise Refused(f"refused: {host} resolves to a non-public address ({address})")
    return addresses[0]


def _forget_cookies(client: httpx.AsyncClient, host: str) -> None:
    """The shared jar keeps Set-Cookie: a visit must not carry one into the next, or a refresh misses it."""
    jar = client.cookies.jar
    for cookie in list(jar):
        domain = cookie.domain.lstrip(".")
        if host == domain or host.endswith("." + domain):
            jar.clear(cookie.domain, cookie.path, cookie.name)


async def _walk(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, list[httpx.Response], int, list[str]]:
    """GET with redirects followed by hand, each hop checked. Returns final, hops, TTFB ms, each one's URL by name."""
    hops: list[httpx.Response] = []
    urls: list[str] = []
    for _ in range(MAX_HOPS + 1):
        target = httpx.URL(url)
        if target.scheme not in ("http", "https"):
            raise Refused(f"refused: a redirect to {target.scheme}:")
        host = target.raw_host.decode("ascii")
        address = await checked_address(host)
        # Connect to the checked address with the name in Host and SNI, so DNS cannot rebind between check and
        # connect. Connection: close stops a pooled socket opened for one SNI being reused for another name.
        pinned = str(target.copy_with(host=address))
        headers = {**visit_headers(), "host": target.netloc.decode("ascii"), "connection": "close"}
        headers_at: list[float] = []

        async def trace(name, info, headers_at=headers_at):
            if name.endswith("receive_response_headers.complete"):
                headers_at.append(time.monotonic())

        async with http.domain_slot(host):
            start = time.monotonic()
            resp = await http.request(
                client,
                "GET",
                pinned,
                headers=headers,
                follow_redirects=False,
                extensions={"trace": trace, "sni_hostname": host},
            )
        ttfb = int(((headers_at[0] if headers_at else time.monotonic()) - start) * 1000)
        _forget_cookies(client, host)
        _forget_cookies(client, address)  # the jar keys on the request host, which is now the address
        urls.append(url)
        location = resp.headers.get("location")
        if not (resp.is_redirect and location):
            return resp, hops, ttfb, urls
        hops.append(resp)
        url = str(target.join(location))  # against the name: a relative Location must not turn into the address
    raise httpx.TooManyRedirects(f"more than {MAX_HOPS} redirects", request=resp.request)


def _cap(text: str) -> str:
    return text if len(text) <= _VALUE_CAP else text[:_VALUE_CAP] + "…"


def _cookie(header: str) -> tuple[str, str]:
    """Name and flags of one Set-Cookie. The value is dropped here, first: it is often a live session token."""
    first, *attrs = header.split(";")
    name = first.split("=", 1)[0].strip()
    flags = {a.split("=", 1)[0].strip().lower(): a.partition("=")[2].strip() for a in attrs}
    samesite = flags.get("samesite")
    parts = [
        "Secure" if "secure" in flags else "not Secure",
        "HttpOnly" if "httponly" in flags else "not HttpOnly",
        f"SameSite={samesite}" if samesite else "no SameSite",
    ]
    return name, ", ".join(parts)


class _Meta(HTMLParser):
    """OpenGraph, Twitter card and generator meta tags; everything else in the page is ignored."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        key = (a.get("property") or a.get("name") or "").strip().lower()
        if key.startswith(("og:", "twitter:")) or key == "generator":
            self.tags.append((key, a.get("content", "").strip()))


@fetcher(
    id="site-http",
    accepts=[EntityType.DOMAIN, EntityType.URL],
    name="Site visit: HTTP",
    note="One GET from your IP with a browser User-Agent; the site sees it. Tech entries are hints, not proof.",
    contacts_target=True,
)
async def site_http(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    url = value if entity_type is EntityType.URL else f"https://{value}/"
    resp, hops, ttfb, urls = await _walk(client, url)
    findings = [
        Finding(label="status", value=f"{resp.status_code} {resp.reason_phrase}".strip()),
        Finding(label="time to first byte", value=f"{ttfb} ms"),
    ]
    findings += [
        Finding(label="redirect", value=f"{hop.status_code} {at}") for hop, at in zip(hops, urls, strict=False)
    ]
    if hops:
        findings.append(Finding(label="final URL", value=urls[-1]))
    for name in SECURITY_HEADERS:
        got = resp.headers.get(name)
        if got is None:
            findings.append(Finding(label="missing header", value=name))
        else:
            findings.append(Finding(label="security header", value=_cap(f"{name}: {got}")))
    cookies = dict(_cookie(h) for r in (*hops, resp) for h in r.headers.get_list("set-cookie"))
    findings += [Finding(label="cookie", value=f"{name}: {flags}") for name, flags in cookies.items() if name]
    for header in ("server", "x-powered-by"):
        if got := resp.headers.get(header):
            findings.append(Finding(label="tech hint", value=_cap(f"{header}: {got}")))
    for header, cdn in CDN_HEADERS.items():
        if header in resp.headers:
            findings.append(Finding(label="tech hint", value=f"{cdn} ({header} header)"))
    for name in cookies:
        hint = next((tech for prefix, tech in COOKIE_HINTS.items() if name.lower().startswith(prefix)), None)
        if hint:
            findings.append(Finding(label="tech hint", value=f"{hint} ({name} cookie)"))
    if "html" in resp.headers.get("content-type", ""):
        parser = _Meta()
        parser.feed(resp.text)
        parser.close()
        for key, content in parser.tags[:30]:
            if key == "generator":
                findings.append(Finding(label="tech hint", value=_cap(f"generator: {content}")))
            else:
                findings.append(Finding(label=key, value=_cap(content)))
    return findings


def _cert_name(rdns) -> str:
    """getpeercert's ((("commonName", "x"),), ...) as the organisation, else the common name."""
    fields = {k: v for rdn in rdns for k, v in rdn}
    return fields.get("organizationName") or fields.get("commonName") or ""


async def _handshake(address: str, host: str, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:  # the retry after a verification failure, for protocol and cipher only
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    _, writer = await asyncio.open_connection(address, 443, ssl=ctx, server_hostname=host)
    try:
        tls = writer.get_extra_info("ssl_object")
        return tls.getpeercert(), tls.version(), tls.cipher()
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


@fetcher(
    id="site-tls",
    accepts=[EntityType.DOMAIN, EntityType.URL],
    name="Site visit: TLS certificate",
    note="One handshake on 443 from your IP. Leaf certificate only, as served to you now; a CDN's may be shared.",
    contacts_target=True,
)
async def site_tls(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    host = httpx.URL(scheme="https", host=host_of(value, entity_type)).raw_host.decode("ascii")  # IDNA, as sent
    findings: list[Finding] = []
    async with asyncio.timeout(TLS_TIMEOUT):
        # Connect to the checked address, SNI by name: DNS cannot change its answer between check and connect.
        address = await checked_address(host)
        try:
            cert, version, cipher = await _handshake(address, host, verify=True)
        except ssl.SSLCertVerificationError as exc:
            findings.append(Finding(label="verification failed", value=exc.verify_message or str(exc)))
            cert, version, cipher = await _handshake(address, host, verify=False)
        except ssl.SSLError:
            raise
        except OSError as exc:
            raise ConnectionError(f"could not connect to {host} on 443") from exc
    if cert:
        findings.append(Finding(label="issuer", value=_cert_name(cert.get("issuer", ()))))
        subject = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
        if cn := subject.get("commonName"):
            findings.append(Finding(label="subject", value=cn))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
        findings += [Finding(label="SAN", value=san) for san in sans[:20]]
        if len(sans) > 20:
            findings.append(Finding(label="note", value=f"{len(sans) - 20} more names not shown", note=True))
        findings.append(Finding(label="valid from", value=cert.get("notBefore", "")))
        if not_after := cert.get("notAfter"):
            findings.append(Finding(label="valid until", value=not_after))
            days = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
            findings.append(Finding(label="days left", value=str(days)))
    findings.append(Finding(label="protocol", value=version or "unknown"))
    if cipher:
        findings.append(Finding(label="cipher", value=f"{cipher[0]} ({cipher[2]}-bit)"))
    return findings


async def _file(client: httpx.AsyncClient, url: str) -> httpx.Response | str:
    """The file's final response, or a one-line reason it is absent or unreadable; refusals included, per file."""
    try:
        resp, _, _, _ = await _walk(client, url)
    except (Refused, httpx.HTTPError) as exc:
        return f"could not read: {_reason(exc)}"
    # An HTML answer to a plain-text or XML path is a soft 404: a site that routes every path to its app.
    if resp.status_code in (404, 410) or "html" in resp.headers.get("content-type", ""):
        return "absent"
    if resp.status_code != 200:
        return f"returned {resp.status_code}"
    return resp


def _robots(text: str) -> list[Finding]:
    rules = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    disallowed = [r.split(":", 1)[1].strip() for r in rules if r.lower().startswith("disallow:")]
    disallowed = [d for d in disallowed if d]  # an empty Disallow allows everything
    sitemaps = [r.split(":", 1)[1].strip() for r in rules if r.lower().startswith("sitemap:")]
    found = [Finding(label="robots.txt", value=f"present, {len(disallowed)} disallow rules")]
    found += [Finding(label="robots sitemap", value=s) for s in sitemaps[:5]]
    found += [Finding(label="robots disallow", value=d) for d in disallowed[:5]]
    return found


def _sitemap(text: str) -> Finding:
    count = len(re.findall(r"<(?:\w+:)?loc>", text))  # the body is already capped at MAX_BODY, so is the count
    kind = "sitemap index of {} sitemaps" if re.search(r"<(?:\w+:)?sitemapindex", text) else "{} URLs"
    return Finding(label="sitemap.xml", value=f"present, {kind.format(count)}")


def _security_txt(text: str) -> list[Finding]:
    signed = "-----BEGIN PGP SIGNED MESSAGE-----" in text
    found = [Finding(label="security.txt", value="present, PGP-signed" if signed else "present, not signed")]
    for line in text.splitlines():
        field, sep, rest = line.partition(":")
        if sep and field.strip().lower() in ("contact", "expires", "policy", "preferred-languages"):
            found.append(Finding(label=f"security.txt {field.strip()}", value=_cap(rest.strip())))
    return found


@fetcher(
    id="site-files",
    accepts=[EntityType.DOMAIN, EntityType.URL],
    name="Site visit: robots, sitemap, security.txt",
    note="Three GETs from your IP. Absent means a 404 or 410; robots.txt asks crawlers, it does not enforce.",
    contacts_target=True,
)
async def site_files(value: str, entity_type: EntityType, client: httpx.AsyncClient) -> list[Finding]:
    host = host_of(value, entity_type)
    findings: list[Finding] = []
    for path, label, parse in (
        ("/robots.txt", "robots.txt", _robots),
        ("/sitemap.xml", "sitemap.xml", lambda text: [_sitemap(text)]),
        ("/.well-known/security.txt", "security.txt", _security_txt),
    ):
        got = await _file(client, str(httpx.URL(scheme="https", host=host, path=path)))  # brackets an IPv6 host
        findings += [Finding(label=label, value=got)] if isinstance(got, str) else parse(got.text)
    return findings
