"""Starlette app. Binds loopback only; this is a local tool, not a service."""

import hashlib
import re
import threading
from itertools import groupby
from pathlib import Path
from urllib.parse import parse_qs, quote

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
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
    list_cases,
    load_case,
    remove_target,
    rename_case,
    save_target,
    star,
    starred_keys,
    unstar,
)
from casefile.catalog import links_for
from casefile.detect import FREE_FORM, detect, is_pivotable
from casefile.export import FORMATS, export_case, media_type, safe_url, when
from casefile.fetchers import (
    SourceResult,
    State,
    fetched_ids,
    fetchers_for,
    registered_fetcher,
    source_name,
    source_note,
    wmn,
)
from casefile.fetchers.http import shared_client
from casefile.linkcheck import check_links, tally
from casefile.types import Candidate, EntityType

_TYPES = {t.value: t for t in EntityType}

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals["export_formats"] = FORMATS
# Empty default so the demo, which has no store behind it, renders; live panels pass the real set.
templates.env.globals["starred_keys"] = frozenset()
templates.env.globals["source_name"] = source_name
templates.env.globals["source_note"] = source_note
templates.env.globals["is_pivotable"] = is_pivotable
templates.env.filters["when"] = lambda ts: when(ts) if ts else "unknown"
# htmx only restores focus after an outerHTML swap if the element had an id; without one it falls to <body>.
templates.env.filters["dom_id"] = lambda parts: (
    "star-" + hashlib.blake2s("\x00".join(parts).encode("utf-8", "surrogatepass"), digest_size=8).hexdigest()
)
templates.env.globals["wmn"] = {"id": wmn.SOURCE_ID, "credit": wmn.CREDIT, "url": wmn.CREDIT_URL}
templates.env.filters["safe_url"] = safe_url


def sections_for(raw: str, results: dict | None = None) -> list[dict]:
    """One entry per reading. `results` prefills the demo's panels; live, a cache hit prefills the same way.

    That is what keeps an on-demand result on the page across reloads: consent is for the egress, and a hit spends none.
    """
    candidates = detect(raw)
    # Free-form is speculative only if something structured also matched, else a bare word demotes everything.
    structured = any(c.type not in FREE_FORM for c in candidates)
    sections = []
    for candidate in candidates:
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
                "starred": frozenset() if results is not None else starred_keys(candidate.type, candidate.value),
                "speculative": structured and candidate.type in FREE_FORM,
            }
        )
    return sections


async def index(request: Request) -> HTMLResponse:
    # autofocus only here: on a content page it defeats the skip link and pulls focus off the results.
    return templates.TemplateResponse(request, "index.html", {"cases": list_cases()[:8], "autofocus": True})


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return RedirectResponse("/")
    sections = sections_for(raw)
    return templates.TemplateResponse(
        request,
        "result.html",
        {"raw": raw, "sections": sections, "all_cases": list_cases()},
    )


def _dead_panel(request: Request, source_id: str, detail: str) -> HTMLResponse:
    """htmx will not swap a 4xx, so refusals render as a panel; a status code leaves the tile on "loading…"."""
    result = SourceResult(source_id, State.ERROR, detail=detail)
    return templates.TemplateResponse(request, "panel.html", {"result": result})


async def panel(request: Request) -> HTMLResponse:
    source_id = request.path_params["source_id"]
    # Allowlist, like the write middleware: a "cross-site" denylist lets same-site and a missing header through.
    if request.headers.get("sec-fetch-site") != "same-origin":
        return _dead_panel(request, source_id, "request must come from casefile's own page")
    value = request.query_params.get("v", "")
    entity_type = _TYPES.get(request.query_params.get("t", ""))
    if entity_type is None:
        return _dead_panel(request, source_id, "unknown entity type")
    rec = registered_fetcher(source_id)
    if rec is not None and entity_type not in rec.accepts:
        return _dead_panel(request, source_id, f"{source_id} does not accept {entity_type}")
    refresh = request.query_params.get("refresh") == "1"
    result = await run_cached(source_id, value, entity_type, shared_client(), refresh=refresh)
    return templates.TemplateResponse(
        request,
        "panel.html",
        {
            "result": result,
            "t": entity_type.value,
            "v": value,
            "starred_keys": starred_keys(entity_type, value),
        },
    )


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _filename_for(case, fmt: str) -> str:
    """ASCII slug for content-disposition: a unicode name breaks the header encoder, CRLF and quotes inject."""
    slug = _UNSAFE_FILENAME.sub("-", case.name).strip("-")
    return f"{slug[:80] or 'case'}.{fmt}"


async def star_route(request: Request) -> Response:
    form = await _form(request)
    entity_type = _TYPES.get(form.get("t", ""))
    if entity_type is None:
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
    # Intent, not toggle: a stale second tab would otherwise un-save rows it never saved.
    action = form.get("action", "star")
    back = form.get("back", "")
    error = None
    try:
        if action == "unstar":
            unstar(entity_type, value, finding)
        else:
            star(entity_type, value, finding)
    except CaseStoreError as exc:
        # htmx does not swap 5xx, so a silent non-save would look identical to a save; show it on the button.
        error = str(exc)
    if back:  # posted from a case page, which has no button to swap
        if error:  # a redirect would look identical to a save; surface the failure instead
            return _mutation_error(request, f"could not update: {error}")
        return RedirectResponse(f"/case/{quote(back)}", status_code=303)
    return templates.TemplateResponse(
        request,
        "star_button.html",
        {
            "t": entity_type.value,
            "v": value,
            "sid": finding.source_id,
            "f": finding,
            "starred": error is None
            and (finding.source_id, finding.label, finding.value) in starred_keys(entity_type, value),
            "error": error,
        },
    )


async def link_check(request: Request) -> Response:
    """On demand, never on page load: one request per link from the user's own IP."""
    if request.headers.get("sec-fetch-site") != "same-origin":
        return PlainTextResponse("request must come from casefile's own page", status_code=403)
    value = request.query_params.get("v", "")
    entity_type = _TYPES.get(request.query_params.get("t", ""))
    if entity_type is None:
        return PlainTextResponse("unknown entity type", status_code=400)
    links = links_for(Candidate(entity_type, value), exclude=fetched_ids())
    verdicts = await check_links(links, shared_client())
    section = {"type": entity_type.value, "value": value, "links": links}
    return templates.TemplateResponse(
        request, "links.html", {"section": section, "verdicts": verdicts, "tally": tally(verdicts)}
    )


async def _form(request: Request) -> dict:
    """parse_qs, not request.form(): htmx posts hx-vals urlencoded and request.form() drags in python-multipart."""
    body = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


async def save_route(request: Request) -> Response:
    """Save one reading into a case: a new one, or an existing one picked by id."""
    form = await _form(request)
    entity_type = _TYPES.get(form.get("t", ""))
    if entity_type is None:
        return PlainTextResponse("unknown entity type", status_code=400)
    value = form.get("v", "")
    if not value:
        return PlainTextResponse("missing target", status_code=400)
    try:
        if form.get("action") == "remove":
            held_by = case_for_target(entity_type, value)
            remove_target(entity_type, value)
            # Removing the last identifier destroys the case, so land where that is visible.
            if held_by and len(held_by.targets) == 1:
                return RedirectResponse("/cases", status_code=303)
            if back := form.get("back"):
                return RedirectResponse(f"/case/{quote(back)}", status_code=303)
        else:
            save_target(entity_type, value, case_id=form.get("case_id") or None, name=form.get("name", ""))
    except CaseStoreError as exc:
        return _mutation_error(request, f"could not save: {exc}")
    return RedirectResponse(f"/q?v={quote(value)}", status_code=303)


def _mutation_error(request: Request, message: str) -> Response:
    return templates.TemplateResponse(
        request, "cases.html", {"cases": list_cases(), "problem": message}, status_code=400
    )


async def case_rename(request: Request) -> Response:
    case_id = request.path_params["case_id"]
    form = await _form(request)
    try:
        rename_case(case_id, form.get("name", ""))
    except CaseStoreError as exc:
        return _mutation_error(request, f"could not rename: {exc}")
    return RedirectResponse(f"/case/{quote(case_id)}", status_code=303)


async def cases(request: Request) -> Response:
    return templates.TemplateResponse(request, "cases.html", {"cases": list_cases()})


async def case_detail(request: Request) -> Response:
    case = load_case(request.path_params["case_id"])
    if case is None:
        return templates.TemplateResponse(request, "cases.html", {"cases": list_cases(), "missing": True})
    # Group by (type, value), not value alone: a username and a company can share a value and must not merge under
    # one type label. _load already orders stars by this key, the same one export._by_target uses.
    groups = [
        (tt, tv, list(rows)) for (tt, tv), rows in groupby(case.stars, key=lambda s: (s.target_type, s.target_value))
    ]
    return templates.TemplateResponse(request, "case.html", {"case": case, "groups": groups})


async def case_export(request: Request) -> Response:
    fmt = request.path_params["fmt"]
    if fmt not in FORMATS:
        return PlainTextResponse(f"unknown format {fmt}", status_code=404)
    case = load_case(request.path_params["case_id"])
    if case is None:
        return PlainTextResponse("no such case", status_code=404)
    body = export_case(case, fmt)
    # filename* carries the real unicode name; the ASCII slug stays as the fallback for browsers that ignore it.
    encoded = quote(case.name, safe="")  # safe='' so a '/' in the name cannot read as a path separator
    disposition = f"attachment; filename=\"{_filename_for(case, fmt)}\"; filename*=UTF-8''{encoded}.{fmt}"
    return Response(body, media_type=media_type(fmt), headers={"content-disposition": disposition})


async def case_delete(request: Request) -> Response:
    try:
        deleted = delete_case(request.path_params["case_id"])
    except CaseStoreError as exc:
        return _mutation_error(request, f"could not delete: {exc}")
    if not deleted:
        return templates.TemplateResponse(request, "cases.html", {"cases": list_cases(), "missing": True})
    return RedirectResponse("/cases", status_code=303)


# Host pin is what stops DNS rebinding, which Sec-Fetch-Site cannot: a rebound name is same-origin to the browser.
_TRUSTED_HOSTS = ["127.0.0.1", "localhost"]


class _RevalidatedStatics(StaticFiles):
    """Starlette sends etag but no cache-control, so a browser can serve the old casefile.js after an upgrade."""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["cache-control"] = "no-cache"
        return response


class _SameOriginWrites(BaseHTTPMiddleware):
    """Every write demands same-origin; middleware, not per route, so a new POST cannot arrive unguarded."""

    async def dispatch(self, request, call_next):
        if request.method not in ("GET", "HEAD") and request.headers.get("sec-fetch-site") != "same-origin":
            return PlainTextResponse("cross-site request refused", status_code=403)
        return await call_next(request)


app = Starlette(
    middleware=[
        Middleware(TrustedHostMiddleware, allowed_hosts=_TRUSTED_HOSTS),
        Middleware(_SameOriginWrites),
    ],
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
        Mount("/static", _RevalidatedStatics(directory=HERE / "static"), name="static"),
    ],
)


def serve(port: int = 8765, host: str = "127.0.0.1", open_browser: bool = True) -> int:
    # Local imports: uvicorn alone is ~70ms, and the CLI, demo build and renderer never start a server.
    import webbrowser

    import uvicorn

    url = f"http://{host}:{port}"
    print(f"casefile is running at {url}")
    print("press ctrl-c to stop")
    if open_browser:
        # ponytail: fixed 0.5s, not a uvicorn hook, so tests importing `app` never open a browser; raise if racy.
        threading.Timer(0.5, webbrowser.open, [url]).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
