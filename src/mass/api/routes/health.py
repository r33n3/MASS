"""Health check endpoints.

Provides liveness, readiness, and detailed health endpoints for
orchestrators, load balancers, and operators.  Per ARCHITECTURE.md
Section 7.2.
"""

import time
from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

router = APIRouter()

# Track startup time for uptime calculation
_startup_time = time.time()


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Health status: healthy, degraded, unhealthy")
    version: str = Field(..., description="Application version")
    uptime_seconds: float = Field(..., description="Uptime in seconds")
    checks: dict[str, Any] | None = None


class ReadinessResponse(BaseModel):
    """Readiness check response."""

    ready: bool = Field(..., description="Whether the service is ready")
    checks: dict[str, bool] = Field(..., description="Individual check results")


# ---------------------------------------------------------------------------
# Subsystem health probes
# ---------------------------------------------------------------------------

async def _check_database() -> dict[str, Any]:
    """Ping PostgreSQL and measure latency."""
    try:
        from sqlalchemy import text
        from mass.storage.database import get_session

        start = time.perf_counter()
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"status": "healthy", "latency_ms": latency_ms}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)[:200]}


async def _check_redis() -> dict[str, Any]:
    """Ping Redis and measure latency."""
    try:
        from mass.storage.cache import get_redis

        start = time.perf_counter()
        redis = await get_redis()
        await redis.ping()
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"status": "healthy", "latency_ms": latency_ms}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)[:200]}


async def _check_queue() -> dict[str, Any]:
    """Check scan queue depth in Redis."""
    try:
        from mass.storage.cache import get_redis

        redis = await get_redis()
        depth = await redis.llen("mass:jobs:queue:scans") or 0
        return {"status": "healthy", "depth": depth}
    except Exception as e:
        return {"status": "degraded", "error": str(e)[:200]}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Returns basic health status for liveness probes.",
)
async def health_check() -> HealthResponse:
    """Basic health check — always returns fast.

    Used by load balancers to verify the process is alive.
    """
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        uptime_seconds=round(time.time() - _startup_time, 1),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
    description="Returns readiness status with actual dependency checks.",
)
async def readiness_check() -> ReadinessResponse:
    """Readiness check — verifies critical dependencies are reachable."""
    db = await _check_database()
    redis = await _check_redis()

    checks = {
        "database": db["status"] == "healthy",
        "redis": redis["status"] == "healthy",
    }

    ready = all(checks.values())
    return ReadinessResponse(ready=ready, checks=checks)


@router.get(
    "/health/detailed",
    summary="Detailed health check",
    description="Returns detailed health status with latency and queue depth.",
)
async def detailed_health_check() -> dict:
    """Detailed health check per ARCHITECTURE.md Section 7.2.

    Returns status, latency, and queue depth for each subsystem.
    """
    db = await _check_database()
    redis = await _check_redis()
    queue = await _check_queue()

    # Determine overall status
    statuses = [db["status"], redis["status"]]
    if all(s == "healthy" for s in statuses):
        overall = "healthy"
    elif any(s == "unhealthy" for s in statuses):
        overall = "unhealthy"
    else:
        overall = "degraded"

    return {
        "status": overall,
        "version": "0.1.0",
        "uptime_seconds": round(time.time() - _startup_time, 1),
        "checks": {
            "database": db,
            "redis": redis,
            "queue": queue,
        },
    }


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    description="Returns Prometheus-formatted metrics.",
)
async def metrics() -> Response:
    """Prometheus metrics endpoint.

    Returns all application metrics in Prometheus exposition format.
    """
    from mass.core.metrics import METRICS
    return Response(
        content=METRICS.export(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
