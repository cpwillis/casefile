"""Starlette app. Binds loopback only; this is a local tool, not a service."""

import re
import threading
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, quote

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

import casefile.fetchers.sources  # noqa: F401 -- registers the fetchers at import
from casefile.cache import cached_result, run_cached
from casefile.cases import (
    CaseStoreError,
    Star,
    case_for_target,
    delete_case,
    is_starred,
    list_cases,
    load_case,
    remove_target,
    rename_case,
    save_target,
    star,
    unstar,
)
from casefile.catalog import links_for
from casefile.detect import detect
from casefile.export import FORMATS, export_case, media_type, safe_url
from casefile.fetchers import SourceResult, State, fetched_ids, fetchers_for, registered_fetcher, wmn
from casefile.fetchers.http import build_client
from casefile.linkcheck import check_links, tally
from casefile.types import Candidate, EntityType

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")
# Exposed to templates so a finding row can render its own star state without a second query
# layer. Kept to one read-only helper rather than handing templates the whole store.
templates.env.globals["export_formats"] = FORMATS
templates.env.globals["wmn"] = {"id": wmn.SOURCE_ID, "credit": wmn.CREDIT, "url": wmn.CREDIT_URL}
# One scheme allowlist for findings, shared with export rather than re-expressed per template.
templates.env.filters["safe_url"] = safe_url
templates.env.globals["is_starred"] = lambda t, v, sid, f: is_starred(
    EntityType(t), v, Star(sid, f.label, f.value, f.url)
)


def sections_for(raw: str, results: dict | None = None) -> list[dict]:
    """The result page's data shape, one entry per reading of the input.

    `results` prefills panels for the static demo build. Live, anything already in the cache is
    prefilled the same way, so reopening a search you have already run paints with the page
    instead of round-tripping, and only genuinely unknown sources self-load. That is also what
    keeps an on-demand result on the page across reloads: consent is for the egress, and a cache
    hit spends none.

    Sharing this with the demo is what stops the two pages drifting: the link filtering, the
    ordering and the panel set are decided once, here.
    """
    sections = []
    for candidate in detect(raw):
        panels = fetchers_for(candidate.type)
        if results is None:
            known = {r.id: hit for r in panels if (hit := cached_result(r.id, candidate.type, candidate.value))}
        else:
            known = results
        sections.append(
            {
                "type": candidate.type.value,
                "value": candidate.value,
                "panels": panels,
                "results": known,
                "links": links_for(candidate, exclude=fetched_ids()),
                "case": None if results is not None else case_for_target(candidate.type, candidate.value),
            }
        )
    return sections


async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"cases": list_cases()[:8]})


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return RedirectResponse("/")  # one homepage, rather than a second render without its context
    sections = sections_for(raw)
    return templates.TemplateResponse(
        request,
        "result.html",
        # every case, so a reading can be joined onto an investigation that already exists
        {"raw": raw, "sections": sections, "all_cases": list_cases()},
    )


def _dead_panel(request: Request, source_id: str, detail: str) -> HTMLResponse:
    """A refused panel is still a rendered panel: htmx will not swap a 4xx, so a status code
    would leave the tile stuck on "loading…" with no reason shown."""
    result = SourceResult(source_id, State.ERROR, detail=detail)
    return templates.TemplateResponse(request, "panel.html", {"result": result})


async def panel(request: Request) -> HTMLResponse:
    source_id = request.path_params["source_id"]
    if request.headers.get("sec-fetch-site") == "cross-site":
        return _dead_panel(request, source_id, "cross-site request refused")
    value = request.query_params.get("v", "")
    try:
        entity_type = EntityType(request.query_params.get("t", ""))
    except ValueError:
        return _dead_panel(request, source_id, "unknown entity type")
    rec = registered_fetcher(source_id)
    if rec is not None and entity_type not in rec.accepts:
        return _dead_panel(request, source_id, f"{source_id} does not accept {entity_type}")
    # refresh=1 is the panel's own re-run control: ignore what is stored, but replace it, so the
    # answer you just asked for is the one the next page load shows.
    refresh = request.query_params.get("refresh") == "1"
    async with build_client() as client:
        result = await run_cached(source_id, value, entity_type, client, refresh=refresh)
    return templates.TemplateResponse(request, "panel.html", {"result": result, "t": entity_type.value, "v": value})


def _same_origin(request: Request) -> bool:
    """Mutations demand same-origin, on top of the Host pin every route already gets.

    A missing Sec-Fetch-Site is refused too: the only legitimate caller of a mutating route is
    this app's own page, and every browser that can reach it sends the header. A page you visit
    while casefile is running must not be able to write to your cases.
    """
    return request.headers.get("sec-fetch-site") == "same-origin"


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _filename_for(case, fmt: str) -> str:
    """A latin-1-safe, quote-free, newline-free download name.

    case.name defaults to a third-party-influenced value. A raw unicode name raises
    UnicodeEncodeError in the header encoder, a CRLF injects a header, and a quote corrupts the
    filename, so it is reduced to a conservative ASCII slug rather than escaped.
    """
    slug = _UNSAFE_FILENAME.sub("-", case.name).strip("-")
    return f"{slug[:80] or 'case'}.{fmt}"


async def star_route(request: Request) -> Response:
    """Star or unstar one finding, returning the button's replacement."""
    if not _same_origin(request):
        return PlainTextResponse("cross-site request refused", status_code=403)
    # Parsed with stdlib rather than request.form(), which pulls in python-multipart. htmx posts
    # hx-vals as urlencoded, so parse_qs is all that is needed and the dependency budget holds.
    body = (await request.body()).decode("utf-8", "replace")
    form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
    try:
        entity_type = EntityType(form.get("t", ""))
    except ValueError:
        return PlainTextResponse("unknown entity type", status_code=400)
    value = form.get("v", "")
    finding = Star(
        source_id=form.get("source_id", ""),
        label=form.get("label", ""),
        value=form.get("value", ""),
        url=form.get("url", "") or None,
    )
    if not value or not finding.source_id:
        return PlainTextResponse("missing target or source", status_code=400)
    # The button states its intent rather than toggling server state. A second tab showing a
    # stale page would otherwise un-save rows it never saved, cascading the case away silently.
    action = form.get("action", "star")
    error = None
    try:
        if action == "unstar":
            unstar(entity_type, value, finding)
        else:
            star(entity_type, value, finding)
    except CaseStoreError as exc:
        # Shown on the button rather than 500ing. htmx does not swap 5xx, so a silent non-save
        # would look identical to a successful one.
        error = str(exc)
    return templates.TemplateResponse(
        request,
        "star_button.html",
        {
            "t": entity_type.value,
            "v": value,
            "sid": finding.source_id,
            "f": finding,
            "starred": error is None and is_starred(entity_type, value, finding),
            "error": error,
        },
    )


async def link_check(request: Request) -> Response:
    """Probe one reading's links and re-render the list with what came back.

    On demand, never on page load: it is one request per link from your IP, which is the same
    consent question the WhatsMyName checker asks.
    """
    if request.headers.get("sec-fetch-site") == "cross-site":
        return PlainTextResponse("cross-site request refused", status_code=403)
    value = request.query_params.get("v", "")
    try:
        entity_type = EntityType(request.query_params.get("t", ""))
    except ValueError:
        return PlainTextResponse("unknown entity type", status_code=400)
    links = links_for(Candidate(entity_type, value), exclude=fetched_ids())
    async with build_client() as client:
        verdicts = await check_links(links, client)
    section = {"type": entity_type.value, "value": value, "links": links}
    return templates.TemplateResponse(
        request, "links.html", {"section": section, "verdicts": verdicts, "tally": tally(verdicts)}
    )


def _form(body: str) -> dict:
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


async def save_route(request: Request) -> Response:
    """Save one reading into a case: a new one, or an existing one picked by id.

    This is the thing that was missing: until now a case could only come into being as a side
    effect of starring a finding, so a search worth keeping but with nothing yet worth starring
    could not be kept at all.
    """
    if not _same_origin(request):
        return PlainTextResponse("cross-site request refused", status_code=403)
    form = _form((await request.body()).decode("utf-8", "replace"))
    try:
        entity_type = EntityType(form.get("t", ""))
    except ValueError:
        return PlainTextResponse("unknown entity type", status_code=400)
    value = form.get("v", "")
    if not value:
        return PlainTextResponse("missing target", status_code=400)
    try:
        if form.get("action") == "remove":
            remove_target(entity_type, value)
        else:
            save_target(entity_type, value, case_id=form.get("case_id") or None, name=form.get("name", ""))
    except CaseStoreError as exc:
        return PlainTextResponse(f"could not save: {exc}", status_code=200)
    return RedirectResponse(f"/q?v={quote(value)}", status_code=303)


async def case_rename(request: Request) -> Response:
    if not _same_origin(request):
        return PlainTextResponse("cross-site request refused", status_code=403)
    case_id = request.path_params["case_id"]
    form = _form((await request.body()).decode("utf-8", "replace"))
    try:
        rename_case(case_id, form.get("name", ""))
    except CaseStoreError as exc:
        return PlainTextResponse(f"could not rename: {exc}", status_code=400)
    return RedirectResponse(f"/case/{quote(case_id)}", status_code=303)


async def cases(request: Request) -> Response:
    return templates.TemplateResponse(request, "cases.html", {"cases": list_cases()})


async def case_detail(request: Request) -> Response:
    case = load_case(request.path_params["case_id"])
    if case is None:
        return templates.TemplateResponse(request, "cases.html", {"cases": list_cases(), "missing": True})
    return templates.TemplateResponse(request, "case.html", {"case": case})


async def case_export(request: Request) -> Response:
    fmt = request.path_params["fmt"]
    if fmt not in FORMATS:
        return PlainTextResponse(f"unknown format {fmt}", status_code=404)
    case = load_case(request.path_params["case_id"])
    if case is None:
        return PlainTextResponse("no such case", status_code=404)
    body = export_case(case, fmt)
    return Response(
        body,
        media_type=media_type(fmt),
        headers={"content-disposition": f'attachment; filename="{_filename_for(case, fmt)}"'},
    )


async def case_delete(request: Request) -> Response:
    if not _same_origin(request):
        return PlainTextResponse("cross-site request refused", status_code=403)
    delete_case(request.path_params["case_id"])
    return RedirectResponse("/cases", status_code=303)


# Pinning Host is what survives DNS rebinding: Sec-Fetch-Site cannot help, because to the
# browser a rebound name is same-origin. Applied as middleware rather than per route so that a
# new route cannot be added unguarded, which is how /panel, the one route with outbound egress,
# ended up as the only sensitive route without the pin.
_TRUSTED_HOSTS = ["127.0.0.1", "localhost"]

app = Starlette(
    middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=_TRUSTED_HOSTS)],
    routes=[
        Route("/", index),
        Route("/q", result),
        Route("/panel/{source_id}", panel),
        Route("/star", star_route, methods=["POST"]),
        Route("/save", save_route, methods=["POST"]),
        Route("/links", link_check),
        Route("/case/{case_id}/rename", case_rename, methods=["POST"]),
        Route("/cases", cases),
        Route("/case/{case_id}", case_detail),
        Route("/case/{case_id}/export.{fmt}", case_export),
        Route("/case/{case_id}/delete", case_delete, methods=["POST"]),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ],
)


def serve(port: int = 8765, host: str = "127.0.0.1", open_browser: bool = True) -> int:
    url = f"http://{host}:{port}"
    print(f"casefile is running at {url}")
    print("press ctrl-c to stop")
    if open_browser:
        # ponytail: fixed 0.5s delay rather than a uvicorn startup hook, so tests that exercise
        # `app` can never launch a browser. Raise it if a cold browser ever races the bind.
        threading.Timer(0.5, webbrowser.open, [url]).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
