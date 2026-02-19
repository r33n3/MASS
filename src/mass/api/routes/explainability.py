"""Explainability endpoints.

Generate human-readable explanations of security findings, attack chains,
scan results, and remediation plans.
Per ARCHITECTURE.md Section 8.1 — Explainability module slot.
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
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
    RemediationPlanRequest,
    RemediationPlanResponse,
)
from mass.api.services import explainability as svc

logger = logging.getLogger(__name__)

router = APIRouter()


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
    return RemediationPlanResponse(**result)


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
