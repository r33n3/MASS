"""API schema models.

Pydantic models for API request/response validation.
"""

from mass.api.schemas.common import (
    ErrorResponse,
    PaginatedResponse,
    SuccessResponse,
)
from mass.api.schemas.auth import (
    TokenRequest,
    TokenResponse,
    APIKeyCreate,
    APIKeyResponse,
    APIKeyListResponse,
)
from mass.api.schemas.deployment import (
    DeploymentCreate,
    DeploymentUpdate,
    DeploymentResponse,
    DeploymentListResponse,
    ComponentResponse,
)
from mass.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanListResponse,
    ScanStatusResponse,
)
from mass.api.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingSummary,
)
from mass.api.schemas.compliance import (
    FrameworkResponse,
    FrameworkListResponse,
    AssessmentRequest,
    AssessmentResponse,
)
from mass.api.schemas.report import (
    ReportResponse,
    ReportListResponse,
    ExportRequest,
    CompareRequest,
)

__all__ = [
    # Common
    "ErrorResponse",
    "PaginatedResponse",
    "SuccessResponse",
    # Auth
    "TokenRequest",
    "TokenResponse",
    "APIKeyCreate",
    "APIKeyResponse",
    "APIKeyListResponse",
    # Deployment
    "DeploymentCreate",
    "DeploymentUpdate",
    "DeploymentResponse",
    "DeploymentListResponse",
    "ComponentResponse",
    # Scan
    "ScanCreate",
    "ScanResponse",
    "ScanListResponse",
    "ScanStatusResponse",
    # Finding
    "FindingResponse",
    "FindingListResponse",
    "FindingSummary",
    # Compliance
    "FrameworkResponse",
    "FrameworkListResponse",
    "AssessmentRequest",
    "AssessmentResponse",
    # Report
    "ReportResponse",
    "ReportListResponse",
    "ExportRequest",
    "CompareRequest",
]
