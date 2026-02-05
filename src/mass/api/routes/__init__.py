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
    discovery,
    dashboard,
    remediations,
    scan_targets,
    interrogation,
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
    "discovery",
    "dashboard",
    "remediations",
    "scan_targets",
    "interrogation",
]
