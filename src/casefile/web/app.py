"""Starlette app. Binds loopback only; this is a local tool, not a service."""

import re
import threading
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

import casefile.fetchers.sources  # noqa: F401 -- registers the fetchers at import
from casefile.cache import run_cached
from casefile.cases import CaseStoreError, Star, delete_case, is_starred, list_cases, load_case, star, unstar
from casefile.detect import detect
from casefile.export import FORMATS, export_case
from casefile.fetchers import SourceResult, State, fetchers_for, registered_fetcher
from casefile.fetchers.http import build_client
from casefile.report import links_for
from casefile.types import EntityType

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")
# Exposed to templates so a finding row can render its own star state without a second query
# layer. Kept to one read-only helper rather than handing templates the whole store.
templates.env.globals["is_starred"] = lambda t, v, sid, f: is_starred(
    EntityType(t), v, Star(sid, f.label, f.value, f.url)
)


def _panels_for(entity_type) -> list:
    """The registry rows a type's panels render from. Every id fetchers_for yields is registered
    by construction, so these are never None."""
    return [registered_fetcher(source_id) for source_id in fetchers_for(entity_type)]


def sections_for(raw: str, results: dict | None = None) -> list[dict]:
    """The result page's data shape, one entry per reading of the input.

    `results` prefills panels for the static demo build. Live it is empty and every panel
    self-loads. Sharing this with the demo is what stops the two pages drifting: the link
    filtering, the ordering and the panel set are decided once, here.
    """
    sections = []
    for candidate in detect(raw):
        sections.append(
            {
                "type": candidate.type.value,
                "value": candidate.value,
                "panels": _panels_for(candidate.type),
                "results": results or {},
                # a source with a fetcher is shown as a panel, so listing it again as a link
                # would be the same source twice
                "links": [link for link in links_for(candidate) if registered_fetcher(link.id) is None],
            }
        )
    return sections


async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"cases": list_cases()[:8]})


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return templates.TemplateResponse(request, "index.html")
    return templates.TemplateResponse(request, "result.html", {"raw": raw, "sections": sections_for(raw)})


async def panel(request: Request) -> HTMLResponse:
    source_id = request.path_params["source_id"]
    if request.headers.get("sec-fetch-site") == "cross-site":
        result = SourceResult(source_id, State.ERROR, detail="cross-site request refused")
        return templates.TemplateResponse(request, "panel.html", {"result": result})
    value = request.query_params.get("v", "")
    try:
        entity_type = EntityType(request.query_params.get("t", ""))
    except ValueError:
        result = SourceResult(source_id, State.ERROR, detail="unknown entity type")
        return templates.TemplateResponse(request, "panel.html", {"result": result})
    rec = registered_fetcher(source_id)
    if rec is not None and entity_type not in rec.accepts:
        result = SourceResult(source_id, State.ERROR, detail=f"{source_id} does not accept {entity_type}")
        return templates.TemplateResponse(request, "panel.html", {"result": result})
    async with build_client() as client:
        result = await run_cached(source_id, value, entity_type, client)
    return templates.TemplateResponse(request, "panel.html", {"result": result, "t": entity_type.value, "v": value})


_MEDIA = {"md": "text/markdown; charset=utf-8", "json": "application/json", "html": "text/html; charset=utf-8"}


_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")


def _local_host(request: Request) -> bool:
    """Sec-Fetch-Site alone does not survive DNS rebinding: a rebound name is same-origin to the
    browser. Pinning Host means a foreign name cannot reach these routes at all."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
    return host in _ALLOWED_HOSTS


def _same_origin(request: Request) -> bool:
    """Mutations demand same-origin, which is stricter than the read-only panel guard.

    A missing Sec-Fetch-Site is refused too: the only legitimate caller of a mutating route is
    this app's own page, and every browser that can reach it sends the header. A page you visit
    while casefile is running must not be able to write to your cases.
    """
    return _local_host(request) and request.headers.get("sec-fetch-site") == "same-origin"


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _filename_for(case, fmt: str) -> str:
    """A latin-1-safe, quote-free, newline-free download name.

    case.value is third-party-influenced text. A raw unicode value raises UnicodeEncodeError in
    the header encoder, a CRLF injects a header, and a quote corrupts the filename, so it is
    reduced to a conservative ASCII slug rather than escaped.
    """
    slug = _UNSAFE_FILENAME.sub("-", f"{case.entity_type}-{case.value}").strip("-")
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
    try:
        if action == "unstar":
            unstar(entity_type, value, finding)
        else:
            star(entity_type, value, finding)
    except CaseStoreError as exc:
        # Show the failure on the button rather than 500ing. htmx does not swap 5xx, so a
        # silent non-save would look identical to a successful one.
        return templates.TemplateResponse(
            request,
            "star_button.html",
            {
                "t": entity_type.value,
                "v": value,
                "sid": finding.source_id,
                "f": finding,
                "starred": False,
                "error": str(exc),
            },
        )
    return templates.TemplateResponse(
        request,
        "star_button.html",
        {
            "t": entity_type.value,
            "v": value,
            "sid": finding.source_id,
            "f": finding,
            "starred": is_starred(entity_type, value, finding),
        },
    )


async def cases(request: Request) -> Response:
    if not _local_host(request):
        return PlainTextResponse("forbidden host", status_code=403)
    return templates.TemplateResponse(request, "cases.html", {"cases": list_cases()})


async def case_detail(request: Request) -> Response:
    if not _local_host(request):
        return PlainTextResponse("forbidden host", status_code=403)
    case = load_case(request.path_params["case_id"])
    if case is None:
        return templates.TemplateResponse(request, "cases.html", {"cases": list_cases(), "missing": True})
    return templates.TemplateResponse(request, "case.html", {"case": case})


async def case_export(request: Request) -> Response:
    if not _local_host(request):
        return PlainTextResponse("forbidden host", status_code=403)
    fmt = request.path_params["fmt"]
    if fmt not in FORMATS:
        return PlainTextResponse(f"unknown format {fmt}", status_code=404)
    case = load_case(request.path_params["case_id"])
    if case is None:
        return PlainTextResponse("no such case", status_code=404)
    body = export_case(case, fmt)
    return Response(
        body,
        media_type=_MEDIA[fmt],
        headers={"content-disposition": f'attachment; filename="{_filename_for(case, fmt)}"'},
    )


async def case_delete(request: Request) -> Response:
    if not _same_origin(request):
        return PlainTextResponse("cross-site request refused", status_code=403)
    delete_case(request.path_params["case_id"])
    return RedirectResponse("/cases", status_code=303)


app = Starlette(
    routes=[
        Route("/", index),
        Route("/q", result),
        Route("/panel/{source_id}", panel),
        Route("/star", star_route, methods=["POST"]),
        Route("/cases", cases),
        Route("/case/{case_id}", case_detail),
        Route("/case/{case_id}/export.{fmt}", case_export),
        Route("/case/{case_id}/delete", case_delete, methods=["POST"]),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ]
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
