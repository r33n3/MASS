"""FastAPI application factory.

Creates and configures the MASS API application.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

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
    chat,
    targets,
    docs,
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

    # Mark any scans left in "running"/"pending" as failed (stale from previous crash)
    try:
        from mass.storage.database import get_session
        from sqlalchemy import update
        from mass.storage.models.deployment import Scan

        async with get_session() as session:
            result = await session.execute(
                update(Scan)
                .where(Scan.status.in_(["running", "pending"]))
                .values(
                    status="failed",
                    error_message="Server restarted while scan was in progress",
                )
            )
            if result.rowcount:
                await session.commit()
                logger.warning(
                    "Cleaned up %d stale running/pending scans from previous session",
                    result.rowcount,
                )
            else:
                await session.rollback()
    except Exception as e:
        logger.debug("Stale scan cleanup skipped: %s", e)

    # Start WebSocket Redis pub/sub listener for cross-process broadcasting
    try:
        from mass.dashboard.websocket import manager as ws_manager
        await ws_manager.start_redis_listener()
        logger.info("WebSocket Redis pub/sub listener started")
    except Exception as e:
        logger.debug("WebSocket Redis listener not started: %s", e)

    yield

    # Shutdown - close WebSocket Redis listener
    try:
        from mass.dashboard.websocket import manager as ws_manager
        await ws_manager.shutdown()
    except Exception:
        pass

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
        description="Model & Application Security Suite - AI Deployment Security Platform",
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

    # Add authentication middleware (extracts keys; enforces in production)
    from mass.api.middleware.auth import AuthMiddleware
    app.add_middleware(AuthMiddleware)

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
    app.include_router(chat.router, prefix=f"{api_prefix}/chat", tags=["Chat"])
    app.include_router(targets.router, prefix=f"{api_prefix}/targets", tags=["Targets"])
    app.include_router(docs.router, prefix=f"{api_prefix}/docs", tags=["Documentation"])

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

    # Serve /data/ static files (mascot image, etc.)
    data_dir = Path("/app/data")
    if data_dir.is_dir():
        app.mount("/data", StaticFiles(directory=str(data_dir)), name="data")

    return app


# For uvicorn direct execution
app = create_app()
