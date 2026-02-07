"""UI routes for the dashboard.

Serves the HTML interface for the dashboard from
static files in the static directory.
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse


router = APIRouter(tags=["ui"])

# Path to static directory
STATIC_DIR = Path(__file__).parent / "static"


def read_dashboard_html() -> str:
    """Read the dashboard HTML from the static file."""
    index_path = STATIC_DIR / "index.html"
    return index_path.read_text(encoding="utf-8")


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Serve the dashboard home page."""
    return HTMLResponse(content=read_dashboard_html())


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    """Serve the scan detail page."""
    return HTMLResponse(content=read_dashboard_html())
