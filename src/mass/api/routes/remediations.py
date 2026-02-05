"""Remediation template endpoints.

CRUD operations for managing remediation guidance templates.
Templates are global (not tenant-scoped) but require authentication.
"""

import json

from fastapi import APIRouter, HTTPException, Query, status

from mass.api.dependencies import (
    AdminDep,
    CurrentTenantDep,
    DBSession,
    PaginationDep,
)
from mass.storage.repositories.remediation import RemediationTemplateRepository
from mass.api.schemas.remediation import (
    RemediationTemplateCreate,
    RemediationTemplateUpdate,
    RemediationTemplateResponse,
    RemediationTemplateListResponse,
    GuardrailExample,
    CodeExample,
    ReferenceLink,
)
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.storage.models.remediation import RemediationTemplate

router = APIRouter()


def _json_dumps(value) -> str | None:
    """Serialize a value to JSON string, or None if empty."""
    if value is None:
        return None
    if isinstance(value, list):
        return json.dumps([
            item.model_dump() if hasattr(item, "model_dump") else item
            for item in value
        ])
    return json.dumps(value)


def _json_loads(value: str | None, default=None):
    """Parse a JSON string, returning default if None/invalid."""
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _template_to_response(template: RemediationTemplate) -> RemediationTemplateResponse:
    """Convert DB model to response schema."""
    guardrail_examples = None
    raw_ge = _json_loads(template.guardrail_examples)
    if raw_ge:
        try:
            guardrail_examples = [GuardrailExample(**g) for g in raw_ge]
        except (TypeError, ValueError):
            guardrail_examples = None

    code_examples = None
    raw_ce = _json_loads(template.code_examples)
    if raw_ce:
        try:
            code_examples = [CodeExample(**c) for c in raw_ce]
        except (TypeError, ValueError):
            code_examples = None

    references = None
    raw_refs = _json_loads(template.references)
    if raw_refs:
        try:
            references = [ReferenceLink(**r) for r in raw_refs]
        except (TypeError, ValueError):
            references = None

    return RemediationTemplateResponse(
        id=template.id,
        category=template.category,
        subcategory=template.subcategory,
        title=template.title,
        summary=template.summary,
        description=template.description,
        severity_default=template.severity_default,
        steps=_json_loads(template.steps),
        guardrail_examples=guardrail_examples,
        code_examples=code_examples,
        cwe_ids=_json_loads(template.cwe_ids),
        owasp_ids=_json_loads(template.owasp_ids),
        mitre_ids=_json_loads(template.mitre_ids),
        references=references,
        estimated_effort=template.estimated_effort,
        is_active=template.is_active,
        version=template.version,
        created_at=template.created_at,
        updated_at=template.updated_at,
    )


@router.get(
    "",
    response_model=RemediationTemplateListResponse,
    summary="List remediation templates",
    description="List all remediation templates with optional category filter.",
)
async def list_templates(
    tenant: CurrentTenantDep,
    db: DBSession,
    pagination: PaginationDep,
    category: str | None = Query(None, description="Filter by attack category"),
    is_active: bool | None = Query(None, description="Filter by active status"),
) -> RemediationTemplateListResponse:
    """List remediation templates."""
    repo = RemediationTemplateRepository(db)

    filters = {}
    if category:
        filters["category"] = category
    if is_active is not None:
        filters["is_active"] = is_active

    templates = await repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        order_by="category",
        **filters,
    )
    total = await repo.count(**filters)

    items = [_template_to_response(t) for t in templates]

    return RemediationTemplateListResponse(
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
    response_model=RemediationTemplateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create remediation template",
    description="Create a new remediation template.",
)
async def create_template(
    request: RemediationTemplateCreate,
    tenant: AdminDep,
    db: DBSession,
) -> RemediationTemplateResponse:
    """Create a new remediation template."""
    repo = RemediationTemplateRepository(db)

    template = RemediationTemplate(
        category=request.category,
        subcategory=request.subcategory,
        title=request.title,
        summary=request.summary,
        description=request.description,
        severity_default=request.severity_default,
        steps=_json_dumps(request.steps),
        guardrail_examples=_json_dumps(request.guardrail_examples),
        code_examples=_json_dumps(request.code_examples),
        cwe_ids=_json_dumps(request.cwe_ids),
        owasp_ids=_json_dumps(request.owasp_ids),
        mitre_ids=_json_dumps(request.mitre_ids),
        references=_json_dumps(request.references),
        estimated_effort=request.estimated_effort,
    )

    created = await repo.create(template)
    return _template_to_response(created)


@router.get(
    "/by-category/{category}",
    response_model=RemediationTemplateResponse,
    summary="Get template by category",
    description="Look up a remediation template by attack category.",
)
async def get_template_by_category(
    category: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    subcategory: str | None = Query(None, description="Optional subcategory"),
) -> RemediationTemplateResponse:
    """Get a remediation template by category with subcategory fallback."""
    repo = RemediationTemplateRepository(db)

    template = await repo.get_by_category(category, subcategory)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation template found for category '{category}'",
        )

    return _template_to_response(template)


@router.get(
    "/{template_id}",
    response_model=RemediationTemplateResponse,
    summary="Get remediation template",
    description="Get a specific remediation template by ID.",
)
async def get_template(
    template_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
) -> RemediationTemplateResponse:
    """Get a remediation template by ID."""
    repo = RemediationTemplateRepository(db)

    template = await repo.get(template_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation template not found",
        )

    return _template_to_response(template)


@router.patch(
    "/{template_id}",
    response_model=RemediationTemplateResponse,
    summary="Update remediation template",
    description="Update a remediation template.",
)
async def update_template(
    template_id: str,
    request: RemediationTemplateUpdate,
    tenant: AdminDep,
    db: DBSession,
) -> RemediationTemplateResponse:
    """Update a remediation template."""
    repo = RemediationTemplateRepository(db)

    template = await repo.get(template_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation template not found",
        )

    updates = {}
    if request.title is not None:
        updates["title"] = request.title
    if request.summary is not None:
        updates["summary"] = request.summary
    if request.description is not None:
        updates["description"] = request.description
    if request.severity_default is not None:
        updates["severity_default"] = request.severity_default
    if request.steps is not None:
        updates["steps"] = _json_dumps(request.steps)
    if request.guardrail_examples is not None:
        updates["guardrail_examples"] = _json_dumps(request.guardrail_examples)
    if request.code_examples is not None:
        updates["code_examples"] = _json_dumps(request.code_examples)
    if request.cwe_ids is not None:
        updates["cwe_ids"] = _json_dumps(request.cwe_ids)
    if request.owasp_ids is not None:
        updates["owasp_ids"] = _json_dumps(request.owasp_ids)
    if request.mitre_ids is not None:
        updates["mitre_ids"] = _json_dumps(request.mitre_ids)
    if request.references is not None:
        updates["references"] = _json_dumps(request.references)
    if request.estimated_effort is not None:
        updates["estimated_effort"] = request.estimated_effort
    if request.is_active is not None:
        updates["is_active"] = request.is_active

    if updates:
        expected_version = template.version
        updates["version"] = expected_version + 1
        template = await repo.update(template, **updates)

        # Verify version was actually incremented (detect concurrent modification)
        if template.version != expected_version + 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Template was modified concurrently, please retry",
            )

    return _template_to_response(template)


@router.delete(
    "/{template_id}",
    response_model=SuccessResponse,
    summary="Delete remediation template",
    description="Deactivate a remediation template (soft delete).",
)
async def delete_template(
    template_id: str,
    tenant: AdminDep,
    db: DBSession,
) -> SuccessResponse:
    """Deactivate a remediation template."""
    repo = RemediationTemplateRepository(db)

    template = await repo.get(template_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation template not found",
        )

    await repo.update(template, is_active=False)
    return SuccessResponse(message="Remediation template deactivated")


@router.post(
    "/seed",
    response_model=SuccessResponse,
    summary="Seed default templates",
    description="Seed or reset the default remediation templates.",
)
async def seed_templates(
    tenant: AdminDep,
    db: DBSession,
) -> SuccessResponse:
    """Seed default remediation templates."""
    from mass.storage.seed.remediation_seed import seed_remediation_templates

    count = await seed_remediation_templates(db)
    return SuccessResponse(message=f"Seeded {count} remediation templates")
