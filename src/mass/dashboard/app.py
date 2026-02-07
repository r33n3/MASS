"""Dashboard application factory.

Creates and configures a lightweight FastAPI application that serves
the MASS dashboard frontend. This is a pure frontend server - all API
calls from the dashboard go to the main MASS API backend.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware


@dataclass
class DashboardConfig:
    """Configuration for the dashboard."""

    # Server settings
    host: str = "127.0.0.1"
    port: int = 8080
    debug: bool = False

    # Security
    allowed_origins: list[str] = field(default_factory=lambda: ["*"])

    # Paths
    static_dir: Path | None = None

    # Features
    enable_ui: bool = True
    enable_websocket: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "enable_ui": self.enable_ui,
        }


def create_app(config: DashboardConfig | None = None) -> FastAPI:
    """Create the dashboard FastAPI application.

    This is a frontend-only server. The dashboard HTML/JS connects
    to the main MASS API backend at a configurable endpoint URL.

    Args:
        config: Dashboard configuration.

    Returns:
        Configured FastAPI application.
    """
    config = config or DashboardConfig()

    app = FastAPI(
        title="MASS Dashboard",
        description="MASS Dashboard - Model & Application Security Suite",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store config in app state
    app.state.config = config

    # Mount static files for assets (mascot, etc.)
    project_root = Path(__file__).parent.parent.parent.parent
    data_dir = project_root / "data"
    if data_dir.exists():
        app.mount("/data", StaticFiles(directory=str(data_dir)), name="data")

    # Mount dashboard static files (CSS, JS, images)
    static_dir = config.static_dir or Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Mount UI routes (serves index.html)
    if config.enable_ui:
        from mass.dashboard.ui import router as ui_router
        app.include_router(ui_router)

    # WebSocket for real-time updates (proxied or direct)
    if config.enable_websocket:
        from mass.dashboard.websocket import router as ws_router
        app.include_router(ws_router)

    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    debug: bool = False,
    **kwargs: Any,
) -> None:
    """Run the dashboard server.

    Args:
        host: Host to bind to.
        port: Port to listen on.
        debug: Enable debug mode.
        **kwargs: Additional configuration options.
    """
    import uvicorn

    config = DashboardConfig(host=host, port=port, debug=debug, **kwargs)
    app = create_app(config)

    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=debug,
    )
