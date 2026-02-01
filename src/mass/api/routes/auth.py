"""Authentication endpoints.

Handles token generation and API key management.
"""

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    APIKeyRepo,
    PaginationDep,
)
from mass.api.schemas.auth import (
    TokenRequest,
    TokenResponse,
    APIKeyCreate,
    APIKeyResponse,
    APIKeyListResponse,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.middleware.auth import generate_api_key, hash_api_key, get_key_prefix

router = APIRouter()


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get access token",
    description="Exchange API key for a short-lived access token.",
)
async def get_token(request: TokenRequest) -> TokenResponse:
    """Get an access token using API key credentials.

    This endpoint implements OAuth2 client credentials flow.
    """
    # TODO: Implement proper token generation with JWT
    if not request.client_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_secret (API key) is required",
        )

    # For now, return a placeholder token
    return TokenResponse(
        access_token="placeholder_token",
        token_type="Bearer",
        expires_in=3600,
        scope=request.scope,
    )


@router.get(
    "/keys",
    response_model=APIKeyListResponse,
    summary="List API keys",
    description="List all API keys for the current tenant.",
)
async def list_api_keys(
    tenant: CurrentTenantDep,
    api_key_repo: APIKeyRepo,
    pagination: PaginationDep,
) -> APIKeyListResponse:
    """List all API keys for the authenticated tenant."""
    keys = await api_key_repo.list_by_tenant(
        tenant_id=tenant.tenant_id,
        offset=pagination.offset,
        limit=pagination.limit,
    )

    total = await api_key_repo.count_by_tenant(tenant.tenant_id)

    items = [
        APIKeyResponse(
            id=key.id,
            name=key.name,
            description=key.description,
            key_prefix=key.key_prefix,
            is_active=key.is_active,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            use_count=key.use_count or 0,
            created_at=key.created_at,
            updated_at=key.updated_at,
        )
        for key in keys
    ]

    return APIKeyListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.post(
    "/keys",
    response_model=APIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API key",
    description="Create a new API key. The full key is only shown once.",
)
async def create_api_key(
    request: APIKeyCreate,
    tenant: CurrentTenantDep,
    api_key_repo: APIKeyRepo,
) -> APIKeyResponse:
    """Create a new API key.

    The full key is only returned in this response and cannot be retrieved later.
    """
    # Generate the key
    full_key, key_hash = generate_api_key()
    key_prefix = get_key_prefix(full_key)

    # Create the key in the database
    from mass.storage.models.tenant import APIKey

    api_key = APIKey(
        tenant_id=tenant.tenant_id,
        name=request.name,
        description=request.description,
        key_prefix=key_prefix,
        key_hash=key_hash,
        is_active=True,
        expires_at=request.expires_at,
    )

    created_key = await api_key_repo.create(api_key)

    return APIKeyResponse(
        id=created_key.id,
        name=created_key.name,
        description=created_key.description,
        key_prefix=created_key.key_prefix,
        key=full_key,  # Only shown on creation
        is_active=created_key.is_active,
        expires_at=created_key.expires_at,
        use_count=0,
        created_at=created_key.created_at,
        updated_at=created_key.updated_at,
    )


@router.get(
    "/keys/{key_id}",
    response_model=APIKeyResponse,
    summary="Get API key",
    description="Get details of a specific API key.",
)
async def get_api_key_details(
    key_id: str,
    tenant: CurrentTenantDep,
    api_key_repo: APIKeyRepo,
) -> APIKeyResponse:
    """Get details of a specific API key."""
    key = await api_key_repo.get(key_id)

    if not key or key.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    return APIKeyResponse(
        id=key.id,
        name=key.name,
        description=key.description,
        key_prefix=key.key_prefix,
        is_active=key.is_active,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        use_count=key.use_count or 0,
        created_at=key.created_at,
        updated_at=key.updated_at,
    )


@router.delete(
    "/keys/{key_id}",
    response_model=SuccessResponse,
    summary="Revoke API key",
    description="Revoke an API key, making it permanently unusable.",
)
async def revoke_api_key(
    key_id: str,
    tenant: CurrentTenantDep,
    api_key_repo: APIKeyRepo,
) -> SuccessResponse:
    """Revoke an API key.

    This deactivates the key permanently. It cannot be reactivated.
    """
    key = await api_key_repo.get(key_id)

    if not key or key.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    await api_key_repo.update(key, is_active=False)

    return SuccessResponse(message="API key revoked successfully")
