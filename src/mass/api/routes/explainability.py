"""Explainability endpoints.

Generate human-readable explanations of security findings, attack chains,
scan results, and remediation plans.
Per ARCHITECTURE.md Section 8.1 — Explainability module slot.
"""

import json
import logging

from fastapi import APIRouter, HTTPException, Query

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    ExplanationRepo,
    FindingRepo,
    ScanRepo,
)
from mass.api.schemas.explainability import (
    ExplainChainRequest,
    ExplainChainResponse,
    ExplainFindingRequest,
    ExplainFindingResponse,
    ExplainScanRequest,
    ExplainScanResponse,
    ExplainabilityStatusResponse,
    ExplanationListResponse,
    RemediationPlanRequest,
    RemediationPlanResponse,
)
from mass.api.schemas.common import PaginationMeta
from mass.api.services import explainability as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------

async def _persist_explanation(
    repo: "ExplanationRepo",
    tenant_id: str,
    explanation_type: str,
    content: dict,
    scan_id: str | None = None,
    finding_id: str | None = None,
    audience: str = "developer",
    depth: str = "standard",
    generated_by: str = "template",
) -> str | None:
    """Persist an explanation to the DB. Returns the explanation ID or None."""
    try:
        from mass.storage.models.ai_artifacts import Explanation

        exp = Explanation(
            tenant_id=tenant_id,
            scan_id=scan_id,
            finding_id=finding_id,
            explanation_type=explanation_type,
            audience=audience,
            depth=depth,
            generated_by=generated_by,
            content=json.dumps(content),
        )
        created = await repo.create(exp)
        logger.info("Persisted explanation %s (type=%s)", created.id, explanation_type)
        return created.id
    except Exception as e:
        logger.warning("Failed to persist explanation: %s", e)
        return None


# ---------------------------------------------------------------------------
# Explain a finding
# ---------------------------------------------------------------------------

@router.post(
    "/finding",
    response_model=ExplainFindingResponse,
    summary="Explain a finding",
    description=(
        "Generate a human-readable explanation of a security finding, "
        "including risk description, attack chain, remediation, and compliance context."
    ),
)
async def explain_finding(
    body: ExplainFindingRequest,
    tenant: CurrentTenantDep,
    finding_repo: FindingRepo,
    explanation_repo: ExplanationRepo,
) -> ExplainFindingResponse:
    # Load finding from DB
    finding_model = await finding_repo.get(body.finding_id)
    if not finding_model or finding_model.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "id": finding_model.id,
        "title": finding_model.title,
        "description": finding_model.description,
        "severity": finding_model.severity,
        "category": finding_model.category,
        "evidence": finding_model.evidence,
        "remediation": finding_model.remediation,
        "file_path": finding_model.file_path,
        "line_number": finding_model.line_number,
        "code_snippet": finding_model.code_snippet,
        "cwe_id": finding_model.cwe_id,
        "owasp_category": finding_model.owasp_category,
        "mitre_technique": finding_model.mitre_technique,
    }

    result = await svc.explain_finding(
        finding=finding_dict,
        audience=body.audience.value,
        depth=body.depth.value,
        include_attack_chain=body.include_attack_chain,
        include_remediation=body.include_remediation,
        include_compliance=body.include_compliance,
    )

    await _persist_explanation(
        explanation_repo,
        tenant_id=tenant.tenant_id,
        explanation_type="finding",
        content=result,
        scan_id=finding_model.scan_id,
        finding_id=finding_model.id,
        audience=body.audience.value,
        depth=body.depth.value,
        generated_by=result.get("generated_by", "template"),
    )

    return ExplainFindingResponse(**result)


# ---------------------------------------------------------------------------
# Explain attack chains in a scan
# ---------------------------------------------------------------------------

@router.post(
    "/chains",
    response_model=ExplainChainResponse,
    summary="Explain attack chains",
    description="Analyze scan findings to identify and explain potential attack chains.",
)
async def explain_chains(
    body: ExplainChainRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    explanation_repo: ExplanationRepo,
) -> ExplainChainResponse:
    scan = await scan_repo.get(body.scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_models = await finding_repo.list(offset=0, limit=10000, scan_id=body.scan_id)
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
        }
        for f in finding_models
    ]

    result = await svc.explain_chains(
        scan_id=body.scan_id,
        findings=findings,
        audience=body.audience.value,
        max_chains=body.max_chains,
    )

    await _persist_explanation(
        explanation_repo,
        tenant_id=tenant.tenant_id,
        explanation_type="chains",
        content=result,
        scan_id=body.scan_id,
        audience=body.audience.value,
    )

    return ExplainChainResponse(**result)


# ---------------------------------------------------------------------------
# Explain full scan results
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=ExplainScanResponse,
    summary="Explain scan results",
    description="Generate a comprehensive human-readable explanation of scan results.",
)
async def explain_scan(
    body: ExplainScanRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    explanation_repo: ExplanationRepo,
) -> ExplainScanResponse:
    scan = await scan_repo.get(body.scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_models = await finding_repo.list(offset=0, limit=10000, scan_id=body.scan_id)
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "file_path": f.file_path,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
        }
        for f in finding_models
    ]

    result = await svc.explain_scan(
        scan_id=body.scan_id,
        findings=findings,
        audience=body.audience.value,
        depth=body.depth.value,
        max_findings=body.max_findings,
    )

    await _persist_explanation(
        explanation_repo,
        tenant_id=tenant.tenant_id,
        explanation_type="scan",
        content=result,
        scan_id=body.scan_id,
        audience=body.audience.value,
        depth=body.depth.value,
    )

    return ExplainScanResponse(**result)


# ---------------------------------------------------------------------------
# Remediation plan
# ---------------------------------------------------------------------------

@router.post(
    "/remediation-plan",
    response_model=RemediationPlanResponse,
    summary="Generate remediation plan",
    description="Generate a prioritized remediation plan from scan findings.",
)
async def remediation_plan(
    body: RemediationPlanRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    explanation_repo: ExplanationRepo,
) -> RemediationPlanResponse:
    scan = await scan_repo.get(body.scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_models = await finding_repo.list(offset=0, limit=10000, scan_id=body.scan_id)
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "remediation": f.remediation,
        }
        for f in finding_models
    ]

    result = await svc.generate_remediation_plan(
        scan_id=body.scan_id,
        findings=findings,
        max_items=body.max_items,
        group_by=body.group_by,
    )

    await _persist_explanation(
        explanation_repo,
        tenant_id=tenant.tenant_id,
        explanation_type="remediation_plan",
        content=result,
        scan_id=body.scan_id,
    )

    return RemediationPlanResponse(**result)


# ---------------------------------------------------------------------------
# GET endpoints for persisted explanations
# ---------------------------------------------------------------------------

@router.get(
    "/by-finding/{finding_id}",
    response_model=ExplanationListResponse,
    summary="Get explanations for a finding",
)
async def get_explanations_by_finding(
    finding_id: str,
    tenant: CurrentTenantDep,
    explanation_repo: ExplanationRepo,
) -> ExplanationListResponse:
    items = await explanation_repo.get_by_finding(finding_id, tenant_id=tenant.tenant_id)
    return ExplanationListResponse(
        items=[
            {
                "id": e.id,
                "explanation_type": e.explanation_type,
                "scan_id": e.scan_id,
                "finding_id": e.finding_id,
                "audience": e.audience,
                "depth": e.depth,
                "generated_by": e.generated_by,
                "content": json.loads(e.content) if e.content else {},
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in items
        ],
        pagination=PaginationMeta(
            total=len(items), offset=0, limit=len(items) or 100, has_more=False,
        ),
    )


@router.get(
    "/by-scan/{scan_id}",
    response_model=ExplanationListResponse,
    summary="Get explanations for a scan",
)
async def get_explanations_by_scan(
    scan_id: str,
    tenant: CurrentTenantDep,
    explanation_repo: ExplanationRepo,
    explanation_type: str | None = Query(default=None, description="Filter: finding, scan, chains, remediation_plan"),
) -> ExplanationListResponse:
    items = await explanation_repo.get_by_scan(
        scan_id,
        explanation_type=explanation_type,
        tenant_id=tenant.tenant_id,
    )
    return ExplanationListResponse(
        items=[
            {
                "id": e.id,
                "explanation_type": e.explanation_type,
                "scan_id": e.scan_id,
                "finding_id": e.finding_id,
                "audience": e.audience,
                "depth": e.depth,
                "generated_by": e.generated_by,
                "content": json.loads(e.content) if e.content else {},
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in items
        ],
        pagination=PaginationMeta(
            total=len(items), offset=0, limit=len(items) or 100, has_more=False,
        ),
    )


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=ExplainabilityStatusResponse,
    summary="Explainability module status",
)
async def module_status(tenant: CurrentTenantDep) -> ExplainabilityStatusResponse:
    stats = await svc.get_stats()

    llm_available = False
    try:
        from mass.core.config import get_settings
        settings = get_settings()
        llm_available = bool(settings.default_provider and settings.default_provider != "none")
    except Exception:
        pass

    return ExplainabilityStatusResponse(
        status="healthy",
        explanations_generated=stats.get("explanations_generated", 0),
        cache_size=stats.get("cache_size", 0),
        llm_available=llm_available,
        supported_audiences=["developer", "security_engineer", "executive", "compliance_officer"],
    )
