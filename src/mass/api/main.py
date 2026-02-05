"""FastAPI application factory.

Creates and configures the MASS API application.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import JSONResponse

from mass.core.config import get_settings
from mass.api.middleware.errors import setup_exception_handlers
from mass.api.middleware.logging import RequestLoggingMiddleware
from mass.api.routes import (
    health,
    auth,
    deployments,
    scans,
    analyze,
    compliance,
    reports,
    webhooks,
    admin,
    discovery,
    dashboard,
    remediations,
    scan_targets,
    interrogation,
    browse,
    mcp_interrogation,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler.

    Manages startup and shutdown events.
    """
    import logging

    logger = logging.getLogger(__name__)

    # Startup
    settings = get_settings()
    app.state.settings = settings

    # Initialize scan queue connection (Redis)
    from mass.api.dependencies import get_scan_queue

    queue = await get_scan_queue()
    if queue is not None:
        logger.info("Scan queue connected (Redis worker dispatch enabled)")
    else:
        logger.warning(
            "Scan queue unavailable - scans will run in-process via BackgroundTasks"
        )

    yield

    # Shutdown - close scan queue Redis connection
    from mass.api.dependencies import close_scan_queue

    await close_scan_queue()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="MASS API",
        description="Model Analysis Security & Safety - AI Deployment Security Scanner",
        version="0.1.0",
        docs_url=None,  # Custom docs endpoint
        redoc_url=None,  # Custom redoc endpoint
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Setup exception handlers
    setup_exception_handlers(app)

    # Include routers
    # Health endpoints (no prefix)
    app.include_router(health.router, tags=["Health"])

    # API v1 routes
    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=f"{api_prefix}/auth", tags=["Authentication"])
    app.include_router(deployments.router, prefix=f"{api_prefix}/deployments", tags=["Deployments"])
    app.include_router(scans.router, prefix=f"{api_prefix}/scans", tags=["Scans"])
    app.include_router(analyze.router, prefix=f"{api_prefix}/analyze", tags=["Direct Analysis"])
    app.include_router(compliance.router, prefix=f"{api_prefix}/compliance", tags=["Compliance"])
    app.include_router(reports.router, prefix=f"{api_prefix}/reports", tags=["Reports"])
    app.include_router(webhooks.router, prefix=f"{api_prefix}/webhooks", tags=["Webhooks"])
    app.include_router(admin.router, prefix=f"{api_prefix}/admin", tags=["Admin"])
    app.include_router(discovery.router, prefix=f"{api_prefix}/discover", tags=["Discovery"])
    app.include_router(dashboard.router, prefix=f"{api_prefix}/dashboard", tags=["Dashboard"])
    app.include_router(remediations.router, prefix=f"{api_prefix}/remediations", tags=["Remediations"])
    app.include_router(scan_targets.router, prefix=f"{api_prefix}/scan-targets", tags=["Scan Targets"])
    app.include_router(interrogation.router, prefix=f"{api_prefix}/interrogation", tags=["Interrogation"])
    app.include_router(browse.router, prefix=f"{api_prefix}/browse", tags=["Browse"])
    app.include_router(mcp_interrogation.router, prefix=f"{api_prefix}/mcp-interrogation", tags=["MCP Interrogation"])

    # WebSocket for real-time scan updates
    from mass.dashboard.websocket import router as ws_router
    app.include_router(ws_router, prefix=f"{api_prefix}/dashboard", tags=["WebSocket"])

    # Custom documentation endpoints
    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui() -> JSONResponse:
        """Swagger UI documentation."""
        return get_swagger_ui_html(
            openapi_url="/api/v1/openapi.json",
            title="MASS API - Documentation",
        )

    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc() -> JSONResponse:
        """ReDoc documentation."""
        return get_redoc_html(
            openapi_url="/api/v1/openapi.json",
            title="MASS API - ReDoc",
        )

    return app


# For uvicorn direct execution
app = create_app()
