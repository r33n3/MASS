"""Compliance endpoints.

Manage compliance frameworks and run assessments.
"""

from fastapi import APIRouter, HTTPException, status

from mass.api.dependencies import (
    CurrentTenantDep,
    ScanRepo,
    PaginationDep,
)
from mass.api.schemas.compliance import (
    FrameworkResponse,
    FrameworkListResponse,
    AssessmentRequest,
    AssessmentResponse,
    ControlResponse,
    FrameworkAssessment,
    ControlAssessment,
    PresetResponse,
)
from mass.api.schemas.common import PaginationMeta

router = APIRouter()


# Placeholder framework definitions
# TODO: Move to compliance module in later iterations
FRAMEWORKS = {
    "owasp:llm": {
        "id": "owasp:llm",
        "name": "OWASP LLM Top 10",
        "short_name": "owasp:llm",
        "version": "2025",
        "description": "OWASP Top 10 for Large Language Model Applications",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "controls": [
            {"id": "LLM01", "name": "Prompt Injection", "description": "Manipulating LLMs via crafted inputs", "severity": "critical"},
            {"id": "LLM02", "name": "Insecure Output Handling", "description": "Neglecting to validate LLM outputs", "severity": "high"},
            {"id": "LLM03", "name": "Training Data Poisoning", "description": "Tampering with training data", "severity": "high"},
            {"id": "LLM04", "name": "Model Denial of Service", "description": "Resource-intensive LLM operations", "severity": "medium"},
            {"id": "LLM05", "name": "Supply Chain Vulnerabilities", "description": "Compromised components in LLM pipeline", "severity": "high"},
            {"id": "LLM06", "name": "Sensitive Information Disclosure", "description": "Leaking confidential data via LLM", "severity": "critical"},
            {"id": "LLM07", "name": "Insecure Plugin Design", "description": "Vulnerable LLM plugins/tools", "severity": "high"},
            {"id": "LLM08", "name": "Excessive Agency", "description": "LLM granted too much autonomy", "severity": "high"},
            {"id": "LLM09", "name": "Overreliance", "description": "Excessive dependence on LLM outputs", "severity": "medium"},
            {"id": "LLM10", "name": "Model Theft", "description": "Unauthorized access to LLM models", "severity": "high"},
        ],
    },
    "mitre:atlas": {
        "id": "mitre:atlas",
        "name": "MITRE ATLAS",
        "short_name": "mitre:atlas",
        "version": "2024",
        "description": "Adversarial Threat Landscape for AI Systems",
        "url": "https://atlas.mitre.org/",
        "controls": [
            {"id": "AML.T0000", "name": "Reconnaissance", "description": "Gathering information about ML systems", "severity": "low"},
            {"id": "AML.T0001", "name": "ML Supply Chain Compromise", "description": "Compromising ML supply chain", "severity": "high"},
            {"id": "AML.T0002", "name": "Data Collection", "description": "Gathering data about ML models", "severity": "medium"},
            {"id": "AML.T0003", "name": "Data Poisoning", "description": "Manipulating training data", "severity": "high"},
            {"id": "AML.T0004", "name": "Model Evasion", "description": "Evading model detection", "severity": "high"},
        ],
    },
    "nist:ai_rmf": {
        "id": "nist:ai_rmf",
        "name": "NIST AI Risk Management Framework",
        "short_name": "nist:ai_rmf",
        "version": "1.0",
        "description": "Framework for managing AI risks",
        "url": "https://www.nist.gov/itl/ai-risk-management-framework",
        "controls": [
            {"id": "GOVERN", "name": "Govern", "description": "Cultivate a culture of risk management", "severity": "medium"},
            {"id": "MAP", "name": "Map", "description": "Understand context and potential impacts", "severity": "medium"},
            {"id": "MEASURE", "name": "Measure", "description": "Analyze and monitor AI risks", "severity": "medium"},
            {"id": "MANAGE", "name": "Manage", "description": "Prioritize and act on risks", "severity": "medium"},
        ],
    },
}

PRESETS = {
    "llm-security": {
        "id": "llm-security",
        "name": "LLM Security",
        "description": "Comprehensive LLM security assessment",
        "frameworks": ["owasp:llm", "mitre:atlas"],
        "categories": ["prompt_injection", "jailbreak", "data_leakage", "excessive_agency"],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise Compliance",
        "description": "Enterprise-grade compliance assessment",
        "frameworks": ["owasp:llm", "nist:ai_rmf"],
        "categories": ["prompt_injection", "sensitive_info", "supply_chain"],
    },
}


@router.get(
    "/frameworks",
    response_model=FrameworkListResponse,
    summary="List compliance frameworks",
    description="List all available compliance frameworks.",
)
async def list_frameworks(
    pagination: PaginationDep,
) -> FrameworkListResponse:
    """List all available compliance frameworks."""
    frameworks = list(FRAMEWORKS.values())

    # Apply pagination
    start = pagination.offset
    end = start + pagination.limit
    paginated = frameworks[start:end]

    items = [
        FrameworkResponse(
            id=f["id"],
            name=f["name"],
            short_name=f["short_name"],
            version=f["version"],
            description=f["description"],
            url=f["url"],
            controls=[
                ControlResponse(
                    id=c["id"],
                    name=c["name"],
                    description=c["description"],
                    severity=c["severity"],
                )
                for c in f["controls"]
            ],
            control_count=len(f["controls"]),
        )
        for f in paginated
    ]

    return FrameworkListResponse(
        items=items,
        pagination=PaginationMeta(
            total=len(frameworks),
            offset=pagination.offset,
            limit=pagination.limit,
            has_more=end < len(frameworks),
        ),
    )


@router.get(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    summary="Get framework",
    description="Get details of a specific compliance framework.",
)
async def get_framework(framework_id: str) -> FrameworkResponse:
    """Get details of a specific compliance framework."""
    framework = FRAMEWORKS.get(framework_id)

    if not framework:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Framework not found",
        )

    return FrameworkResponse(
        id=framework["id"],
        name=framework["name"],
        short_name=framework["short_name"],
        version=framework["version"],
        description=framework["description"],
        url=framework["url"],
        controls=[
            ControlResponse(
                id=c["id"],
                name=c["name"],
                description=c["description"],
                severity=c["severity"],
            )
            for c in framework["controls"]
        ],
        control_count=len(framework["controls"]),
    )


@router.get(
    "/presets",
    response_model=list[PresetResponse],
    summary="List presets",
    description="List available compliance presets.",
)
async def list_presets() -> list[PresetResponse]:
    """List available compliance presets."""
    return [
        PresetResponse(
            id=p["id"],
            name=p["name"],
            description=p["description"],
            frameworks=p["frameworks"],
            categories=p["categories"],
        )
        for p in PRESETS.values()
    ]


@router.post(
    "/assess",
    response_model=AssessmentResponse,
    summary="Run compliance assessment",
    description="Run a compliance assessment against a scan.",
)
async def run_assessment(
    request: AssessmentRequest,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
) -> AssessmentResponse:
    """Run a compliance assessment against scan findings."""
    import uuid
    from datetime import datetime, timezone

    # Verify scan exists and belongs to tenant
    scan = await scan_repo.get(request.scan_id)

    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Validate frameworks
    for fw_id in request.frameworks:
        if fw_id not in FRAMEWORKS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown framework: {fw_id}",
            )

    # TODO: Implement actual assessment logic
    # For now, return a placeholder assessment

    framework_assessments = []
    for fw_id in request.frameworks:
        fw = FRAMEWORKS[fw_id]
        controls = [
            ControlAssessment(
                control_id=c["id"],
                control_name=c["name"],
                status="pass",  # TODO: Actually check findings
                finding_count=0,
            )
            for c in fw["controls"]
        ]

        framework_assessments.append(
            FrameworkAssessment(
                framework_id=fw["id"],
                framework_name=fw["name"],
                overall_status="compliant",
                pass_count=len(controls),
                fail_count=0,
                partial_count=0,
                not_applicable_count=0,
                compliance_percentage=100.0,
                controls=controls,
            )
        )

    return AssessmentResponse(
        id=str(uuid.uuid4()),
        scan_id=request.scan_id,
        created_at=datetime.now(timezone.utc),
        overall_compliance=100.0,
        frameworks=framework_assessments,
        summary="Compliance assessment completed. No violations found.",
    )
