"""Admin endpoints.

Administrative operations and tenant management.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import (
    CurrentTenantDep,
    TenantRepo,
    UserRepo,
    PaginationDep,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse

router = APIRouter()


class TenantCreate(BaseModel):
    """Request to create a tenant."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Tenant name")
    slug: str = Field(..., min_length=1, max_length=100, description="URL-friendly slug")
    description: str | None = Field(default=None, description="Tenant description")
    max_deployments: int = Field(default=100, description="Maximum deployments allowed")
    max_scans_per_month: int = Field(default=1000, description="Maximum scans per month")


class TenantResponse(BaseModel):
    """Tenant response schema."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Tenant ID")
    name: str = Field(..., description="Tenant name")
    slug: str = Field(..., description="URL slug")
    description: str | None = Field(default=None, description="Description")
    is_active: bool = Field(..., description="Whether tenant is active")
    max_deployments: int = Field(..., description="Maximum deployments")
    max_scans_per_month: int = Field(default=1000, description="Maximum monthly scans")
    created_at: datetime = Field(..., description="Creation time")
    updated_at: datetime = Field(..., description="Last update time")


class TenantListResponse(BaseModel):
    """List of tenants."""

    model_config = ConfigDict(extra="forbid")

    items: list[TenantResponse] = Field(..., description="List of tenants")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class SystemStats(BaseModel):
    """System-wide statistics."""

    model_config = ConfigDict(extra="forbid")

    total_tenants: int = Field(..., description="Total number of tenants")
    active_tenants: int = Field(..., description="Active tenants")
    total_deployments: int = Field(..., description="Total deployments")
    total_scans: int = Field(..., description="Total scans")
    total_findings: int = Field(..., description="Total findings")
    scans_last_24h: int = Field(..., description="Scans in last 24 hours")
    findings_last_24h: int = Field(..., description="Findings in last 24 hours")


class UserResponse(BaseModel):
    """User response for admin."""

    model_config = ConfigDict(extra="forbid")

    id: str
    email: str
    full_name: str | None = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserListResponse(BaseModel):
    """List of users."""

    model_config = ConfigDict(extra="forbid")

    items: list[UserResponse]
    pagination: PaginationMeta


@router.get(
    "/stats",
    response_model=SystemStats,
    summary="Get system stats",
    description="Get system-wide statistics (admin only).",
)
async def get_system_stats(
    tenant: CurrentTenantDep,
) -> SystemStats:
    """Get system-wide statistics.

    Requires admin privileges.
    """
    # TODO: Verify admin privileges
    # TODO: Get actual statistics from database

    return SystemStats(
        total_tenants=1,
        active_tenants=1,
        total_deployments=0,
        total_scans=0,
        total_findings=0,
        scans_last_24h=0,
        findings_last_24h=0,
    )


@router.get(
    "/tenants",
    response_model=TenantListResponse,
    summary="List tenants",
    description="List all tenants (admin only).",
)
async def list_tenants(
    tenant: CurrentTenantDep,
    tenant_repo: TenantRepo,
    pagination: PaginationDep,
) -> TenantListResponse:
    """List all tenants.

    Requires admin privileges.
    """
    # TODO: Verify admin privileges

    tenants = await tenant_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
    )

    total = await tenant_repo.count()

    items = [
        TenantResponse(
            id=t.id,
            name=t.name,
            slug=t.slug,
            description=t.description,
            is_active=t.is_active,
            max_deployments=t.max_deployments,
            created_at=t.created_at,
            updated_at=t.updated_at,
        )
        for t in tenants
    ]

    return TenantListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant",
    description="Create a new tenant (admin only).",
)
async def create_tenant(
    request: TenantCreate,
    current_tenant: CurrentTenantDep,
    tenant_repo: TenantRepo,
) -> TenantResponse:
    """Create a new tenant.

    Requires admin privileges.
    """
    from mass.storage.models.tenant import Tenant

    # TODO: Verify admin privileges

    # Check if slug is unique
    existing = await tenant_repo.get_by_slug(request.slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant with this slug already exists",
        )

    tenant = Tenant(
        name=request.name,
        slug=request.slug,
        description=request.description,
        is_active=True,
        max_deployments=request.max_deployments,
    )

    created = await tenant_repo.create(tenant)

    return TenantResponse(
        id=created.id,
        name=created.name,
        slug=created.slug,
        description=created.description,
        is_active=created.is_active,
        max_deployments=created.max_deployments,
        created_at=created.created_at,
        updated_at=created.updated_at,
    )


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    summary="Get tenant",
    description="Get tenant details (admin only).",
)
async def get_tenant(
    tenant_id: str,
    current_tenant: CurrentTenantDep,
    tenant_repo: TenantRepo,
) -> TenantResponse:
    """Get tenant details.

    Requires admin privileges.
    """
    # TODO: Verify admin privileges

    tenant = await tenant_repo.get(tenant_id)

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        description=tenant.description,
        is_active=tenant.is_active,
        max_deployments=tenant.max_deployments,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.delete(
    "/tenants/{tenant_id}",
    response_model=SuccessResponse,
    summary="Deactivate tenant",
    description="Deactivate a tenant (admin only).",
)
async def deactivate_tenant(
    tenant_id: str,
    current_tenant: CurrentTenantDep,
    tenant_repo: TenantRepo,
) -> SuccessResponse:
    """Deactivate a tenant.

    Requires admin privileges.
    """
    # TODO: Verify admin privileges

    tenant = await tenant_repo.get(tenant_id)

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    await tenant_repo.update(tenant, is_active=False)

    return SuccessResponse(message="Tenant deactivated successfully")


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List users",
    description="List all users across tenants (admin only).",
)
async def list_all_users(
    current_tenant: CurrentTenantDep,
    user_repo: UserRepo,
    pagination: PaginationDep,
    tenant_id: str | None = None,
) -> UserListResponse:
    """List all users.

    Requires admin privileges.
    """
    # TODO: Verify admin privileges

    filters = {}
    if tenant_id:
        filters["tenant_id"] = tenant_id

    users = await user_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await user_repo.count(**filters)

    items = [
        UserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            is_active=u.is_active,
            is_verified=u.is_verified,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
        )
        for u in users
    ]

    return UserListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )
