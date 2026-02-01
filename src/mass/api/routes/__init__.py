"""API routes package."""

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
)

__all__ = [
    "health",
    "auth",
    "deployments",
    "scans",
    "analyze",
    "compliance",
    "reports",
    "webhooks",
    "admin",
]
