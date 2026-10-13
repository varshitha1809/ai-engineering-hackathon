"""PHISHDNA AI — FastAPI application.

Run from the repository root:
    uvicorn backend.app.main:app --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import analysis, cases, demo, evaluations, intel, system
from .config import REPO_ROOT, settings
from .security import SecurityMiddleware
from .state import state


@asynccontextmanager
async def lifespan(_app: FastAPI):
    state.startup()
    yield


app = FastAPI(title="PHISHDNA AI", version="1.0.0", lifespan=lifespan,
              description="Evidence-driven phishing & social-engineering investigation API")
app.add_middleware(SecurityMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-API-Key"])

for r in (analysis.router, cases.router, intel.router, evaluations.router, system.router, demo.router):
    app.include_router(r)


DIST = REPO_ROOT / "frontend" / "dist"
if (DIST / "index.html").exists():
    # Serve the production frontend build from the same origin (single-command start). /api routes take precedence.
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        f = (DIST / path).resolve()
        if path and f.is_file() and DIST.resolve() in f.parents:
            return FileResponse(f)
        if path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        return FileResponse(DIST / "index.html")


@app.exception_handler(Exception)
async def unhandled(_request: Request, exc: Exception):
    # never leak internals or message content; the error type is enough for the UI
    state.request_errors += 1
    return JSONResponse({"detail": f"internal error ({type(exc).__name__})"}, status_code=500)
