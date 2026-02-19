"""Supply chain verification endpoints.

Manage packages, generate SBOMs, verify model provenance,
check for vulnerabilities and malicious packages.
Per ARCHITECTURE.md Section 8.1 — Supply Chain module slot.
"""

import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status

from mass.api.dependencies import CurrentTenantDep, PaginationDep
from mass.api.schemas.common import PaginationMeta, SuccessResponse
from mass.api.schemas.supply_chain import (
    ModelVerifyRequest,
    ModelVerifyResponse,
    PackageCreate,
    PackageListResponse,
    PackageResponse,
    PackageUpdate,
    SBOMGenerateRequest,
    SBOMListResponse,
    SBOMResponse,
    SupplyChainScanRequest,
    SupplyChainScanResponse,
    SupplyChainStatusResponse,
    VulnerabilityListResponse,
    VulnerabilityResponse,
)
from mass.api.services import supply_chain as svc

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Package CRUD
# ---------------------------------------------------------------------------

@router.post(
    "/packages",
    response_model=PackageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register package",
    description="Register a package dependency for supply chain tracking.",
)
async def create_package(
    body: PackageCreate,
    tenant: CurrentTenantDep,
) -> PackageResponse:
    record = await svc.create_package(tenant.tenant_id, body.model_dump())
    return PackageResponse(**record)


@router.get(
    "/packages",
    response_model=PackageListResponse,
    summary="List packages",
)
async def list_packages(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    ecosystem: str | None = Query(default=None, description="Filter by ecosystem"),
) -> PackageListResponse:
    items, total = await svc.list_packages(
        tenant_id=tenant.tenant_id,
        ecosystem=ecosystem,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return PackageListResponse(
        items=[PackageResponse(**p) for p in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/packages/{package_id}",
    response_model=PackageResponse,
    summary="Get package",
)
async def get_package(
    package_id: str,
    tenant: CurrentTenantDep,
) -> PackageResponse:
    record = await svc.get_package(package_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Package not found")
    return PackageResponse(**record)


@router.patch(
    "/packages/{package_id}",
    response_model=PackageResponse,
    summary="Update package",
)
async def update_package(
    package_id: str,
    body: PackageUpdate,
    tenant: CurrentTenantDep,
) -> PackageResponse:
    existing = await svc.get_package(package_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Package not found")
    record = await svc.update_package(package_id, body.model_dump(exclude_unset=True))
    return PackageResponse(**record)


@router.delete(
    "/packages/{package_id}",
    response_model=SuccessResponse,
    summary="Delete package",
)
async def delete_package(
    package_id: str,
    tenant: CurrentTenantDep,
) -> SuccessResponse:
    existing = await svc.get_package(package_id)
    if not existing or existing.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Package not found")
    await svc.delete_package(package_id)
    return SuccessResponse(message="Package deleted")


# ---------------------------------------------------------------------------
# SBOM generation
# ---------------------------------------------------------------------------

@router.post(
    "/sbom",
    response_model=SBOMResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate SBOM",
    description="Generate a Software Bill of Materials from registered packages.",
)
async def generate_sbom(
    body: SBOMGenerateRequest,
    tenant: CurrentTenantDep,
) -> SBOMResponse:
    record = await svc.generate_sbom(
        tenant_id=tenant.tenant_id,
        fmt=body.format.value,
        include_transitive=body.include_transitive,
        include_vulnerabilities=body.include_vulnerabilities,
        include_licenses=body.include_licenses,
        scan_id=body.scan_id,
    )
    return SBOMResponse(**record)


@router.get(
    "/sbom",
    response_model=SBOMListResponse,
    summary="List SBOMs",
)
async def list_sboms(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> SBOMListResponse:
    items, total = await svc.list_sboms(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return SBOMListResponse(
        items=[SBOMResponse(**s) for s in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


@router.get(
    "/sbom/{sbom_id}",
    response_model=SBOMResponse,
    summary="Get SBOM",
)
async def get_sbom(
    sbom_id: str,
    tenant: CurrentTenantDep,
) -> SBOMResponse:
    record = await svc.get_sbom(sbom_id)
    if not record or record.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return SBOMResponse(**record)


# ---------------------------------------------------------------------------
# Model provenance verification
# ---------------------------------------------------------------------------

@router.post(
    "/verify-model",
    response_model=ModelVerifyResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Verify model file",
    description="Verify a model file's integrity, provenance, and format security.",
)
async def verify_model(
    body: ModelVerifyRequest,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> ModelVerifyResponse:
    job = await svc.verify_model(
        tenant_id=tenant.tenant_id,
        file_path=body.file_path,
        expected_hash=body.expected_hash,
        source_url=body.source_url,
        model_id=body.model_id,
        check_provenance=body.check_provenance,
        check_signatures=body.check_signatures,
        check_format=body.check_format,
    )
    background_tasks.add_task(svc.run_model_verification, job["job_id"])
    return ModelVerifyResponse(**job)


@router.get(
    "/verify-model/{job_id}",
    response_model=ModelVerifyResponse,
    summary="Get model verification status",
)
async def get_verify_job(
    job_id: str,
    tenant: CurrentTenantDep,
) -> ModelVerifyResponse:
    job = await svc.get_verify_job(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Verification job not found")
    return ModelVerifyResponse(**job)


# ---------------------------------------------------------------------------
# Vulnerability listing
# ---------------------------------------------------------------------------

@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities",
    description="List known vulnerabilities across tracked packages.",
)
async def list_vulnerabilities(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
    package_name: str | None = Query(default=None, description="Filter by package"),
    severity: str | None = Query(default=None, description="Filter by severity"),
) -> VulnerabilityListResponse:
    items, total = await svc.list_vulnerabilities(
        tenant_id=tenant.tenant_id,
        package_name=package_name,
        severity=severity,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return VulnerabilityListResponse(
        items=[VulnerabilityResponse(**v) for v in items],
        pagination=PaginationMeta(
            total=total,
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=(pagination.offset + pagination.limit) < total,
        ),
    )


# ---------------------------------------------------------------------------
# Full supply chain scan
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=SupplyChainScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Run supply chain scan",
    description=(
        "Run a full supply chain verification scan across all registered "
        "packages: vulnerability check, license audit, typosquatting detection."
    ),
)
async def start_scan(
    body: SupplyChainScanRequest,
    tenant: CurrentTenantDep,
    background_tasks: BackgroundTasks,
) -> SupplyChainScanResponse:
    job = await svc.start_supply_chain_scan(tenant.tenant_id, body.model_dump())
    background_tasks.add_task(svc.run_supply_chain_scan, job["job_id"])
    return SupplyChainScanResponse(**job)


@router.get(
    "/scan/{job_id}",
    response_model=SupplyChainScanResponse,
    summary="Get supply chain scan status",
)
async def get_scan(
    job_id: str,
    tenant: CurrentTenantDep,
) -> SupplyChainScanResponse:
    job = await svc.get_scan_job(job_id)
    if not job or job.get("tenant_id") != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return SupplyChainScanResponse(**job)


@router.get(
    "/scans",
    response_model=list[SupplyChainScanResponse],
    summary="List supply chain scans",
)
async def list_scans(
    tenant: CurrentTenantDep,
    pagination: PaginationDep,
) -> list[SupplyChainScanResponse]:
    items, _ = await svc.list_scan_jobs(
        tenant_id=tenant.tenant_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return [SupplyChainScanResponse(**s) for s in items]


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

@router.get(
    "/status",
    response_model=SupplyChainStatusResponse,
    summary="Supply chain module status",
)
async def module_status(tenant: CurrentTenantDep) -> SupplyChainStatusResponse:
    packages, total_pkgs = await svc.list_packages(
        tenant_id=tenant.tenant_id, limit=10000,
    )

    ecosystem_counts: dict[str, int] = {}
    total_vulns = 0
    for pkg in packages:
        eco = pkg.get("ecosystem", "other")
        ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1
        total_vulns += len(pkg.get("vulnerabilities", []))

    sboms, total_sboms = await svc.list_sboms(tenant_id=tenant.tenant_id, limit=1)

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    scans, _ = await svc.list_scan_jobs(tenant_id=tenant.tenant_id, limit=5000)
    recent = sum(1 for s in scans if s.get("created_at", "") >= cutoff)

    return SupplyChainStatusResponse(
        status="healthy",
        total_packages=total_pkgs,
        total_vulnerabilities=total_vulns,
        total_sboms=total_sboms,
        recent_scans=recent,
        packages_by_ecosystem=ecosystem_counts,
    )
