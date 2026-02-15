"""FastAPI application factory.

Creates and configures the MASS API application.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import HTMLResponse, JSONResponse
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
    mcp_audit,
    chat,
    targets,
    docs,
    ollama,
    guardrails_policies,
    sandbox,
    settings as settings_routes,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler.

    Manages startup and shutdown events.
    """
    import json
    import logging
    import os

    # Set up structured logging before anything else
    from mass.core.logging_config import setup_logging
    setup_logging()

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

    # Mark any interrogation jobs left in "running"/"pending" as failed in Redis
    try:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("MASS_REDIS_URL", "redis://localhost:6379/0")
        r = aioredis.from_url(redis_url, decode_responses=True)
        cleaned = 0
        async for key in r.scan_iter(match="mass:interrogation:jobs:*"):
            raw = await r.get(key)
            if not raw:
                continue
            job = json.loads(raw)
            if job.get("status") in ("running", "pending"):
                job["status"] = "failed"
                job["message"] = "Server restarted while interrogation was in progress"
                await r.set(key, json.dumps(job, default=str))
                cleaned += 1
        await r.close()
        if cleaned:
            logger.warning(
                "Cleaned up %d stale running/pending interrogation jobs from Redis",
                cleaned,
            )
    except Exception as e:
        logger.debug("Stale interrogation cleanup skipped: %s", e)

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

    # Shutdown - close LLM connection pools
    try:
        from mass.runners.pool import close_all_pools
        await close_all_pools()
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

    # Add distributed rate limiting (Redis-backed)
    from mass.api.middleware.rate_limit import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware)

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
    app.include_router(mcp_audit.router, prefix=f"{api_prefix}/mcp-audit", tags=["MCP Audit"])
    app.include_router(sandbox.router, prefix=f"{api_prefix}/sandbox", tags=["Sandbox"])
    app.include_router(chat.router, prefix=f"{api_prefix}/chat", tags=["Chat"])
    app.include_router(targets.router, prefix=f"{api_prefix}/targets", tags=["Targets"])
    app.include_router(docs.router, prefix=f"{api_prefix}/docs", tags=["Documentation"])
    app.include_router(ollama.router, prefix=f"{api_prefix}/ollama", tags=["Ollama"])
    app.include_router(guardrails_policies.router, prefix=f"{api_prefix}/guardrails-policies", tags=["Guardrails & Policies"])
    app.include_router(settings_routes.router, prefix=f"{api_prefix}/settings", tags=["Settings"])

    # WebSocket for real-time scan updates
    from mass.dashboard.websocket import router as ws_router
    app.include_router(ws_router, prefix=f"{api_prefix}/dashboard", tags=["WebSocket"])

    # Custom documentation endpoints — dark themed to match MASS dashboard
    _SWAGGER_DARK_CSS = """
    /* MASS Dark Theme for Swagger UI */
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Special+Elite&display=swap');

    html { background: #0a0b09; }
    body { background: #141816 !important; color: #e8e4dc !important; }

    /* Top bar */
    .swagger-ui .topbar { background: #0d100d !important; border-bottom: 1px solid #3a3c38; padding: 8px 0; }
    .swagger-ui .topbar .download-url-wrapper .select-label { color: #a8a498 !important; }
    .swagger-ui .topbar .download-url-wrapper input[type=text] {
        background: #1a1f1c !important; color: #e8e4dc !important;
        border: 1px solid #3a3c38 !important; border-radius: 4px;
    }
    .swagger-ui .topbar .download-url-wrapper .download-url-button {
        background: #6B8E23 !important; color: #0a0b09 !important; border-radius: 4px;
    }
    .swagger-ui .topbar a { font-family: 'Special Elite', monospace; }
    .swagger-ui .topbar img { display: none; }
    .swagger-ui .topbar a::before { content: 'MASS API'; font-size: 1.4em; color: #7FFF00; letter-spacing: 0.05em; }

    /* General info section */
    .swagger-ui .info { margin: 30px 0 20px 0; }
    .swagger-ui .info .title { color: #e8e4dc !important; font-family: 'Special Elite', monospace; }
    .swagger-ui .info .title small { background: #6B8E23 !important; border-radius: 4px; }
    .swagger-ui .info .description p { color: #a8a498 !important; }
    .swagger-ui .info a { color: #7FFF00 !important; }
    .swagger-ui .info .base-url { color: #6b6a60 !important; }

    /* Wrapper / scheme container */
    .swagger-ui .scheme-container { background: #1a1f1c !important; border: 1px solid #3a3c38; box-shadow: none; }
    .swagger-ui .wrapper { background: transparent !important; }

    /* Operation blocks */
    .swagger-ui .opblock { border-radius: 6px !important; border: 1px solid #3a3c38 !important; margin-bottom: 8px; }
    .swagger-ui .opblock .opblock-summary { border: none !important; }
    .swagger-ui .opblock .opblock-summary-description { color: #a8a498 !important; }

    /* HTTP method colors — grunge-tinted */
    .swagger-ui .opblock.opblock-get { background: rgba(107, 142, 35, 0.08) !important; border-color: #6B8E23 !important; }
    .swagger-ui .opblock.opblock-get .opblock-summary-method { background: #6B8E23 !important; }
    .swagger-ui .opblock.opblock-get .opblock-summary { border-color: #6B8E23 !important; }

    .swagger-ui .opblock.opblock-post { background: rgba(127, 255, 0, 0.06) !important; border-color: #5d8a4a !important; }
    .swagger-ui .opblock.opblock-post .opblock-summary-method { background: #5d8a4a !important; }

    .swagger-ui .opblock.opblock-put { background: rgba(212, 160, 58, 0.06) !important; border-color: #c9943a !important; }
    .swagger-ui .opblock.opblock-put .opblock-summary-method { background: #c9943a !important; }

    .swagger-ui .opblock.opblock-delete { background: rgba(196, 92, 58, 0.06) !important; border-color: #c45c3a !important; }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method { background: #c45c3a !important; }

    .swagger-ui .opblock.opblock-patch { background: rgba(154, 205, 50, 0.06) !important; border-color: #9ACD32 !important; }
    .swagger-ui .opblock.opblock-patch .opblock-summary-method { background: #9ACD32 !important; color: #0a0b09 !important; }

    .swagger-ui .opblock .opblock-summary-method { color: #0a0b09 !important; font-weight: 600; border-radius: 4px; }
    .swagger-ui .opblock .opblock-summary-path { color: #e8e4dc !important; }
    .swagger-ui .opblock .opblock-summary-path__deprecated { color: #6b6a60 !important; }

    /* Expanded operation body */
    .swagger-ui .opblock-body { background: #1a1f1c !important; }
    .swagger-ui .opblock-body pre { background: #0d100d !important; color: #9ACD32 !important; border: 1px solid #3a3c38; border-radius: 4px; }
    .swagger-ui .opblock-body pre span { color: #9ACD32 !important; }
    .swagger-ui .opblock-description-wrapper p { color: #a8a498 !important; }
    .swagger-ui .opblock-section-header { background: #242a26 !important; border-bottom: 1px solid #3a3c38; }
    .swagger-ui .opblock-section-header h4 { color: #e8e4dc !important; }

    /* Tag headers */
    .swagger-ui .opblock-tag { color: #e8e4dc !important; border-bottom: 1px solid #3a3c38 !important; font-family: 'IBM Plex Mono', monospace; }
    .swagger-ui .opblock-tag:hover { background: rgba(127, 255, 0, 0.03) !important; }
    .swagger-ui .opblock-tag small { color: #6b6a60 !important; }
    .swagger-ui .opblock-tag a { color: #a8a498 !important; }

    /* Tables */
    .swagger-ui table thead tr th { color: #a8a498 !important; border-bottom: 1px solid #3a3c38 !important; }
    .swagger-ui table tbody tr td { color: #e8e4dc !important; border-bottom: 1px solid #242a26 !important; }
    .swagger-ui .parameters-col_description p { color: #a8a498 !important; }
    .swagger-ui .parameter__name { color: #e8e4dc !important; }
    .swagger-ui .parameter__name.required::after { color: #c45c3a !important; }
    .swagger-ui .parameter__type { color: #9ACD32 !important; font-family: 'IBM Plex Mono', monospace; }

    /* Models / Schemas */
    .swagger-ui section.models { border: 1px solid #3a3c38 !important; border-radius: 6px; }
    .swagger-ui section.models h4 { color: #e8e4dc !important; }
    .swagger-ui section.models .model-container { background: #1a1f1c !important; border: 1px solid #3a3c38 !important; margin: 4px 0; border-radius: 4px; }
    .swagger-ui .model { color: #a8a498 !important; font-family: 'IBM Plex Mono', monospace; }
    .swagger-ui .model-title { color: #e8e4dc !important; }
    .swagger-ui .model .property { color: #e8e4dc !important; }
    .swagger-ui .model .property.primitive { color: #9ACD32 !important; }
    .swagger-ui span.model-title__text { color: #7FFF00 !important; }

    /* Inputs & buttons */
    .swagger-ui input[type=text], .swagger-ui textarea, .swagger-ui select {
        background: #1a1f1c !important; color: #e8e4dc !important;
        border: 1px solid #3a3c38 !important; border-radius: 4px;
    }
    .swagger-ui input:focus, .swagger-ui textarea:focus, .swagger-ui select:focus {
        border-color: #7FFF00 !important; outline: none;
    }
    .swagger-ui .btn { border-radius: 4px; }
    .swagger-ui .btn.execute { background: #6B8E23 !important; color: #0a0b09 !important; border: none; }
    .swagger-ui .btn.execute:hover { background: #7FFF00 !important; }
    .swagger-ui .btn.cancel { border-color: #c45c3a !important; color: #c45c3a !important; }
    .swagger-ui .btn.authorize { color: #7FFF00 !important; border-color: #7FFF00 !important; }

    /* Responses */
    .swagger-ui .responses-inner { background: transparent !important; }
    .swagger-ui .response-col_status { color: #e8e4dc !important; }
    .swagger-ui .response-col_description { color: #a8a498 !important; }
    .swagger-ui .responses-table thead td { color: #a8a498 !important; }
    .swagger-ui .response-col_links { color: #6b6a60 !important; }
    .swagger-ui .response-control-media-type__accept-message { color: #5d8a4a !important; }

    /* Curl / code blocks */
    .swagger-ui .curl-command .copy-to-clipboard button { background: #242a26; border: 1px solid #3a3c38; color: #a8a498; }
    .swagger-ui .copy-to-clipboard button { background: #242a26; }
    .swagger-ui .microlight { background: #0d100d !important; color: #9ACD32 !important; border: 1px solid #3a3c38; border-radius: 4px; }
    .swagger-ui .highlight-code .microlight { background: #0d100d !important; }

    /* JSON syntax highlighting in dark */
    .swagger-ui .highlight-code .microlight .headerline { color: #6b6a60 !important; }

    /* Response codes */
    .swagger-ui .responses-header td { color: #a8a498 !important; }
    .swagger-ui .live-responses-table td { color: #e8e4dc !important; }

    /* Authorize dialog */
    .swagger-ui .dialog-ux .modal-ux { background: #1a1f1c !important; border: 1px solid #3a3c38; }
    .swagger-ui .dialog-ux .modal-ux-header { border-bottom: 1px solid #3a3c38; }
    .swagger-ui .dialog-ux .modal-ux-header h3 { color: #e8e4dc !important; }
    .swagger-ui .dialog-ux .modal-ux-content p { color: #a8a498 !important; }
    .swagger-ui .dialog-ux .modal-ux-content h4 { color: #e8e4dc !important; }
    .swagger-ui .dialog-ux .backdrop-ux { background: rgba(10, 11, 9, 0.8) !important; }

    /* Try it out */
    .swagger-ui .try-out__btn { border-color: #7FFF00 !important; color: #7FFF00 !important; }
    .swagger-ui .try-out__btn:hover { background: rgba(127, 255, 0, 0.1) !important; }

    /* Loading */
    .swagger-ui .loading-container .loading::after { color: #7FFF00 !important; }

    /* Scrollbar */
    .swagger-ui ::-webkit-scrollbar { width: 6px; height: 6px; }
    .swagger-ui ::-webkit-scrollbar-track { background: #141816; }
    .swagger-ui ::-webkit-scrollbar-thumb { background: #3a3c38; border-radius: 3px; }
    .swagger-ui ::-webkit-scrollbar-thumb:hover { background: #4a4c48; }

    /* Filter/search */
    .swagger-ui .filter .operation-filter-input {
        background: #1a1f1c !important; color: #e8e4dc !important;
        border: 1px solid #3a3c38 !important;
    }

    /* Arrow/expand icons */
    .swagger-ui svg.arrow { fill: #a8a498 !important; }
    .swagger-ui .expand-operation svg { fill: #6b6a60 !important; }
    .swagger-ui button { color: #e8e4dc; }

    /* Markdown content */
    .swagger-ui .markdown p, .swagger-ui .markdown li { color: #a8a498 !important; }
    .swagger-ui .markdown code { background: #0d100d; color: #9ACD32; padding: 2px 6px; border-radius: 3px; }

    /* Footer link color fix */
    .swagger-ui a { color: #7FFF00; }
    """

    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui() -> HTMLResponse:
        """Swagger UI documentation — MASS dark theme."""
        html = get_swagger_ui_html(
            openapi_url="/api/v1/openapi.json",
            title="MASS API - Documentation",
            swagger_ui_parameters={
                "deepLinking": True,
                "defaultModelsExpandDepth": 1,
                "docExpansion": "list",
                "filter": True,
                "syntaxHighlight.theme": "monokai",
            },
        )
        # Inject dark theme CSS into the HTML response
        themed = html.body.decode().replace(
            "</head>",
            f"<style>{_SWAGGER_DARK_CSS}</style></head>",
        )
        return HTMLResponse(themed)

    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc() -> HTMLResponse:
        """ReDoc documentation — MASS dark theme."""
        html = get_redoc_html(
            openapi_url="/api/v1/openapi.json",
            title="MASS API - ReDoc",
        )
        redoc_dark = """
        body { background: #141816 !important; color: #e8e4dc !important; }
        .menu-content { background: #0d100d !important; }
        .api-content { background: #141816 !important; }
        a { color: #7FFF00 !important; }
        code { background: #0d100d !important; color: #9ACD32 !important; }
        h1, h2, h3, h4, h5 { color: #e8e4dc !important; }
        """
        themed = html.body.decode().replace(
            "</head>",
            f"<style>{redoc_dark}</style></head>",
        )
        return HTMLResponse(themed)

    # Serve /data/ static files (mascot image, etc.)
    data_dir = Path("/app/data")
    if data_dir.is_dir():
        app.mount("/data", StaticFiles(directory=str(data_dir)), name="data")

    return app


# For uvicorn direct execution
app = create_app()
