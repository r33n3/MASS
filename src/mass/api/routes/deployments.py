"""Deployment endpoints.

CRUD operations for AI deployments.
"""

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    DeploymentRepo,
    PaginationDep,
)
from mass.api.schemas.deployment import (
    DeploymentCreate,
    DeploymentUpdate,
    DeploymentResponse,
    DeploymentListResponse,
    ComponentResponse,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.storage.models.deployment import Deployment

router = APIRouter()


def _deployment_to_response(deployment: Deployment, include_components: bool = False) -> DeploymentResponse:
    """Convert a deployment model to response schema."""
    components = None
    if include_components and deployment.components:
        components = [
            ComponentResponse(
                id=c.id,
                name=c.name,
                component_type=c.component_type,
                description=c.description,
                file_path=c.file_path,
                line_start=c.line_start,
                line_end=c.line_end,
                model_provider=c.model_provider,
                model_name=c.model_name,
                mcp_server_url=c.mcp_server_url,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in deployment.components
        ]

    # Parse tags from JSON string
    import json
    tags = None
    if deployment.tags:
        try:
            tags = json.loads(deployment.tags)
        except (json.JSONDecodeError, TypeError):
            tags = None

    return DeploymentResponse(
        id=deployment.id,
        name=deployment.name,
        description=deployment.description,
        version=deployment.version,
        source_type=deployment.source_type,
        source_path=deployment.source_path,
        source_ref=deployment.source_ref,
        is_active=deployment.is_active,
        last_scanned_at=deployment.last_scanned_at,
        tags=tags,
        components=components,
        component_count=len(deployment.components) if deployment.components else 0,
        scan_count=len(deployment.scans) if hasattr(deployment, "scans") and deployment.scans else 0,
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
    )


@router.get(
    "",
    response_model=DeploymentListResponse,
    summary="List deployments",
    description="List all deployments for the current tenant.",
)
async def list_deployments(
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
    pagination: PaginationDep,
    is_active: bool | None = None,
) -> DeploymentListResponse:
    """List all deployments for the authenticated tenant."""
    filters = {"tenant_id": tenant.tenant_id}
    if is_active is not None:
        filters["is_active"] = is_active

    deployments = await deployment_repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )

    total = await deployment_repo.count(**filters)

    items = [_deployment_to_response(d) for d in deployments]

    return DeploymentListResponse(
        items=items,
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=pagination.offset + len(items) < total,
        ),
    )


@router.post(
    "",
    response_model=DeploymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create deployment",
    description="Create a new deployment to be scanned.",
)
async def create_deployment(
    request: DeploymentCreate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> DeploymentResponse:
    """Create a new deployment."""
    import json

    deployment = Deployment(
        tenant_id=tenant.tenant_id,
        name=request.name,
        description=request.description,
        version=request.version,
        source_type=request.source_type,
        source_path=request.source_path,
        source_ref=request.source_ref,
        tags=json.dumps(request.tags) if request.tags else None,
        is_active=True,
    )

    created = await deployment_repo.create(deployment)

    return _deployment_to_response(created)


@router.get(
    "/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Get deployment",
    description="Get details of a specific deployment.",
)
async def get_deployment(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
    include_components: bool = False,
) -> DeploymentResponse:
    """Get details of a specific deployment."""
    deployment = await deployment_repo.get_with_components(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    return _deployment_to_response(deployment, include_components=include_components)


@router.patch(
    "/{deployment_id}",
    response_model=DeploymentResponse,
    summary="Update deployment",
    description="Update a deployment's metadata.",
)
async def update_deployment(
    deployment_id: str,
    request: DeploymentUpdate,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> DeploymentResponse:
    """Update a deployment."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    # Build update kwargs
    import json
    update_data = {}
    if request.name is not None:
        update_data["name"] = request.name
    if request.description is not None:
        update_data["description"] = request.description
    if request.version is not None:
        update_data["version"] = request.version
    if request.source_path is not None:
        update_data["source_path"] = request.source_path
    if request.source_ref is not None:
        update_data["source_ref"] = request.source_ref
    if request.is_active is not None:
        update_data["is_active"] = request.is_active
    if request.tags is not None:
        update_data["tags"] = json.dumps(request.tags)

    if update_data:
        deployment = await deployment_repo.update(deployment, **update_data)

    return _deployment_to_response(deployment)


@router.delete(
    "/{deployment_id}",
    response_model=SuccessResponse,
    summary="Delete deployment",
    description="Soft-delete a deployment.",
)
async def delete_deployment(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> SuccessResponse:
    """Delete a deployment (soft delete)."""
    deployment = await deployment_repo.get(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    await deployment_repo.soft_delete(deployment)

    return SuccessResponse(message="Deployment deleted successfully")


@router.get(
    "/{deployment_id}/components",
    response_model=list[ComponentResponse],
    summary="List deployment components",
    description="List all components discovered in a deployment.",
)
async def list_deployment_components(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> list[ComponentResponse]:
    """List all components in a deployment."""
    deployment = await deployment_repo.get_with_components(deployment_id)

    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deployment not found",
        )

    return [
        ComponentResponse(
            id=c.id,
            name=c.name,
            component_type=c.component_type,
            description=c.description,
            file_path=c.file_path,
            line_start=c.line_start,
            line_end=c.line_end,
            model_provider=c.model_provider,
            model_name=c.model_name,
            mcp_server_url=c.mcp_server_url,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )
        for c in (deployment.components or [])
    ]
