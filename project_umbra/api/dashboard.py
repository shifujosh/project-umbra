"""
Project Umbra REST API route to serve the web dashboard.
Serves the static index.html at root / for the Cloud Run hosted UI.
"""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse

dashboard_router = APIRouter()
_STATIC = Path(__file__).resolve().parent.parent / "static"


@dashboard_router.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    return FileResponse(_STATIC / "index.html", media_type="text/html")


@dashboard_router.get("/favicon.ico", include_in_schema=False)
async def serve_favicon() -> FileResponse:
    """Serve the current Umbra mark for browsers that request the legacy icon path."""
    return FileResponse(
        _STATIC / "assets" / "favicon-32.png",
        media_type="image/png",
        headers={"Cache-Control": "no-cache, max-age=0"},
    )
