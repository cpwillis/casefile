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

from casefile.report import build_report

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")


async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


async def result(request: Request) -> HTMLResponse:
    raw = request.query_params.get("v", "").strip()
    if not raw:
        return templates.TemplateResponse(request, "index.html")
    sections = build_report(raw)
    return templates.TemplateResponse(request, "result.html", {"raw": raw, "sections": sections})


app = Starlette(
    routes=[
        Route("/", index),
        Route("/q", result),
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
