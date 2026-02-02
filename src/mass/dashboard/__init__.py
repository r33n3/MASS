"""MASS Dashboard for scan monitoring and visualization.

Provides a web-based interface for viewing scan results,
monitoring active scans, and analyzing findings.
"""

from mass.dashboard.app import create_app, DashboardConfig
from mass.dashboard.api import router as api_router

__all__ = [
    "create_app",
    "DashboardConfig",
    "api_router",
]
