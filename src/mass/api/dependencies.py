"""FastAPI dependency injection.

Provides common dependencies for API routes.
"""

from typing import Annotated, AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from mass.core.config import MassSettings, get_settings
from mass.storage.database import get_async_session
from mass.storage.repositories.tenant import TenantRepository, UserRepository, APIKeyRepository
from mass.storage.repositories.deployment import DeploymentRepository
from mass.storage.repositories.scan import ScanRepository
from mass.storage.repositories.finding import FindingRepository
from mass.storage.repositories.report import ReportRepository


# Settings dependency
async def get_app_settings() -> MassSettings:
    """Get application settings."""
    return get_settings()


SettingsDep = Annotated[MassSettings, Depends(get_app_settings)]


# Database session dependency
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async for session in get_async_session():
        yield session


DBSession = Annotated[AsyncSession, Depends(get_db)]


# Repository dependencies
async def get_tenant_repository(db: DBSession) -> TenantRepository:
    """Get tenant repository."""
    return TenantRepository(db)


async def get_user_repository(db: DBSession) -> UserRepository:
    """Get user repository."""
    return UserRepository(db)


async def get_api_key_repository(db: DBSession) -> APIKeyRepository:
    """Get API key repository."""
    return APIKeyRepository(db)


async def get_deployment_repository(db: DBSession) -> DeploymentRepository:
    """Get deployment repository."""
    return DeploymentRepository(db)


async def get_scan_repository(db: DBSession) -> ScanRepository:
    """Get scan repository."""
    return ScanRepository(db)


async def get_finding_repository(db: DBSession) -> FindingRepository:
    """Get finding repository."""
    return FindingRepository(db)


async def get_report_repository(db: DBSession) -> ReportRepository:
    """Get report repository."""
    return ReportRepository(db)


TenantRepo = Annotated[TenantRepository, Depends(get_tenant_repository)]
UserRepo = Annotated[UserRepository, Depends(get_user_repository)]
APIKeyRepo = Annotated[APIKeyRepository, Depends(get_api_key_repository)]
DeploymentRepo = Annotated[DeploymentRepository, Depends(get_deployment_repository)]
ScanRepo = Annotated[ScanRepository, Depends(get_scan_repository)]
FindingRepo = Annotated[FindingRepository, Depends(get_finding_repository)]
ReportRepo = Annotated[ReportRepository, Depends(get_report_repository)]


# Authentication dependencies
class CurrentTenant:
    """Current tenant context."""

    def __init__(self, tenant_id: str, user_id: str | None = None, api_key_id: str | None = None):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.api_key_id = api_key_id


async def get_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Extract API key from headers.

    Supports both X-API-Key header and Bearer token.
    """
    if x_api_key:
        return x_api_key

    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing API key or bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_tenant(
    request: Request,
    api_key: Annotated[str, Depends(get_api_key)],
    api_key_repo: APIKeyRepo,
) -> CurrentTenant:
    """Get current tenant from API key.

    Validates the API key and returns tenant context.
    """
    # TODO: Implement proper API key validation with hashing
    # For now, this is a stub that should be replaced with actual validation

    # Check cache first (request state may have cached tenant)
    if hasattr(request.state, "tenant"):
        return request.state.tenant

    # Look up API key by prefix
    key_prefix = api_key[:12] if len(api_key) >= 12 else api_key
    stored_key = await api_key_repo.get_by_prefix(key_prefix)

    if not stored_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if not stored_key.is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is inactive or expired",
        )

    # Update usage count
    await api_key_repo.increment_use_count(stored_key)

    tenant = CurrentTenant(
        tenant_id=stored_key.tenant_id,
        api_key_id=stored_key.id,
    )

    # Cache on request
    request.state.tenant = tenant

    return tenant


CurrentTenantDep = Annotated[CurrentTenant, Depends(get_current_tenant)]


# Optional authentication (for public endpoints that can be enhanced with auth)
async def get_optional_tenant(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> CurrentTenant | None:
    """Get current tenant if API key is provided, otherwise None."""
    if not x_api_key and not authorization:
        return None

    try:
        api_key = await get_api_key(x_api_key, authorization)
        # Would need api_key_repo here - simplified for stub
        return None  # TODO: Implement full validation
    except HTTPException:
        return None


OptionalTenantDep = Annotated[CurrentTenant | None, Depends(get_optional_tenant)]


# Pagination dependency
class PaginationParams:
    """Pagination parameters."""

    def __init__(
        self,
        offset: int = 0,
        limit: int = 100,
    ):
        if offset < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Offset must be non-negative",
            )
        if limit < 1 or limit > 1000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit must be between 1 and 1000",
            )
        self.offset = offset
        self.limit = limit


PaginationDep = Annotated[PaginationParams, Depends()]
