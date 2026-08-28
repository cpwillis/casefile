"""Starlette app. Binds loopback only; this is a local tool, not a service."""

import threading
import webbrowser
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

import casefile.fetchers.sources  # noqa: F401 -- registers the fetchers at import
from casefile.cache import run_cached
from casefile.detect import detect
from casefile.fetchers import SourceResult, State, fetchers_for, has_fetcher, registered_fetcher
from casefile.fetchers.http import build_client
from casefile.report import links_for
from casefile.types import EntityType

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")


async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return templates.TemplateResponse(request, "index.html")
    sections = []
    for candidate in detect(raw):
        sections.append(
            {
                "type": candidate.type.value,
                "value": candidate.value,
                "panels": fetchers_for(candidate.type),
                "links": [link for link in links_for(candidate) if not has_fetcher(link.id)],
            }
        )
    return templates.TemplateResponse(request, "result.html", {"raw": raw, "sections": sections})


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
    return templates.TemplateResponse(request, "panel.html", {"result": result})


app = Starlette(
    routes=[
        Route("/", index),
        Route("/q", result),
        Route("/panel/{source_id}", panel),
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
