"""MASS Python SDK for AI deployment security scanning.

Provides a clean, high-level API for scanning AI deployments
and analyzing security findings programmatically.

Basic usage:
    from mass.sdk import MASS

    # Create client
    client = MASS()

    # Scan a directory
    result = client.scan("/path/to/deployment")

    # Access findings
    for finding in result.findings:
        print(f"{finding.severity}: {finding.title}")

Async usage:
    from mass.sdk import AsyncMASS

    async def scan():
        client = AsyncMASS()
        result = await client.scan("/path/to/deployment")
        return result.findings
"""

from mass.sdk.client import MASS, MASSClient
from mass.sdk.async_client import AsyncMASS, AsyncMASSClient
from mass.sdk.config import MASSConfig, ScanProfile
from mass.sdk.models import (
    ScanResult,
    Finding,
    ScanSummary,
    ComplianceStatus,
    RiskAssessment,
    VerdictSummary,
    ThreatModelSummary,
)
from mass.sdk.exceptions import (
    MASSError,
    ScanError,
    ConfigurationError,
    ValidationError,
)

__all__ = [
    # Main clients
    "MASS",
    "MASSClient",
    "AsyncMASS",
    "AsyncMASSClient",
    # Configuration
    "MASSConfig",
    "ScanProfile",
    # Models
    "ScanResult",
    "Finding",
    "ScanSummary",
    "ComplianceStatus",
    "RiskAssessment",
    "VerdictSummary",
    "ThreatModelSummary",
    # Exceptions
    "MASSError",
    "ScanError",
    "ConfigurationError",
    "ValidationError",
]

__version__ = "0.1.0"
