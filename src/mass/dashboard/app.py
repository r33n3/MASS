"""Dashboard application factory.

Creates and configures the FastAPI application for the
MASS dashboard with all routes and middleware.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
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
    api_key: str | None = None

    # Paths
    static_dir: Path | None = None
    templates_dir: Path | None = None

    # Features
    enable_api: bool = True
    enable_ui: bool = True
    enable_websocket: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "enable_api": self.enable_api,
            "enable_ui": self.enable_ui,
        }


def create_app(config: DashboardConfig | None = None) -> FastAPI:
    """Create the dashboard FastAPI application.

    Args:
        config: Dashboard configuration.

    Returns:
        Configured FastAPI application.
    """
    config = config or DashboardConfig()

    app = FastAPI(
        title="MASS Dashboard",
        description="Model Analysis Security & Safety Dashboard",
        version="0.1.0",
        docs_url="/api/docs" if config.enable_api else None,
        redoc_url="/api/redoc" if config.enable_api else None,
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
    app.state.scan_store = {}  # In-memory scan storage

    # Mount API routes
    if config.enable_api:
        from mass.dashboard.api import router as api_router
        app.include_router(api_router, prefix="/api")

    # Mount UI routes
    if config.enable_ui:
        from mass.dashboard.ui import router as ui_router
        app.include_router(ui_router)

    # WebSocket for real-time updates
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
