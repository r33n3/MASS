"""Common API schemas.

Shared models for pagination, errors, and responses.
"""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class SuccessResponse(BaseModel):
    """Generic success response."""

    model_config = ConfigDict(extra="forbid")

    success: bool = True
    message: str = "Operation completed successfully"


class ErrorResponse(BaseModel):
    """Error response schema."""

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: dict[str, Any] | None = Field(default=None, description="Additional error details")
    request_id: str | None = Field(default=None, description="Request ID for tracking")


class PaginationMeta(BaseModel):
    """Pagination metadata."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., description="Total number of items")
    offset: int = Field(..., description="Current offset")
    limit: int = Field(..., description="Items per page")
    has_more: bool = Field(..., description="Whether there are more items")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    model_config = ConfigDict(extra="forbid")

    items: list[T] = Field(..., description="List of items")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""

    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class AuditMixin(TimestampMixin):
    """Mixin for audit fields."""

    created_by: str | None = Field(default=None, description="User who created this resource")
    updated_by: str | None = Field(default=None, description="User who last updated this resource")


class IDMixin(BaseModel):
    """Mixin for ID field."""

    id: str = Field(..., description="Unique identifier")


class TenantMixin(BaseModel):
    """Mixin for tenant-scoped resources."""

    tenant_id: str = Field(..., description="Tenant ID")
