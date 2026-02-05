"""Dashboard endpoints.

Provides DB-backed dashboard stats, scan listing, and findings
for the MASS dashboard UI.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from mass.api.dependencies import (
    CurrentTenantDep,
    DBSession,
    ScanRepo,
    FindingRepo,
    DeploymentRepo,
)
from mass.storage.models.deployment import Scan


router = APIRouter()


# Response models

class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_scans: int = 0
    active_scans: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    scans_today: int = 0
    avg_scan_duration: float = 0.0
    total_deployments: int = 0


class DashboardScanItem(BaseModel):
    """Scan item for dashboard listing."""

    scan_id: str
    status: str
    target: str
    profile: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class DashboardFinding(BaseModel):
    """Finding item for dashboard listing."""

    id: str
    title: str
    severity: str
    category: str
    component: str
    file_path: str | None = None
    line_number: int | None = None
    description: str = ""


class GuardrailExampleItem(BaseModel):
    """Guardrail example for dashboard display."""
    framework: str
    title: str
    code: str


class CodeFixExampleItem(BaseModel):
    """Code fix example for dashboard display."""
    language: str
    title: str
    description: str = ""
    code: str


class DashboardFindingDetail(BaseModel):
    """Full finding detail for dashboard."""

    id: str
    title: str
    severity: str
    status: str
    category: str
    component: str
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    description: str = ""
    evidence: str | None = None
    remediation: str | None = None
    remediation_steps: list[str] = []
    guardrail_examples: list[GuardrailExampleItem] = []
    code_fix_examples: list[CodeFixExampleItem] = []
    references: str | None = None
    rule_id: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    mitre_technique: str | None = None
    estimated_effort: str | None = None
    confidence_level: str | None = None
    original_severity: str | None = None


# Endpoints

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    tenant: CurrentTenantDep,
    db: DBSession,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    deployment_repo: DeploymentRepo,
) -> DashboardStats:
    """Get dashboard statistics from the database."""
    tenant_id = tenant.tenant_id

    # Total scans
    total_scans = await scan_repo.count(tenant_id=tenant_id)

    # Active (running) scans
    active_scans = await scan_repo.count(tenant_id=tenant_id, status="running")

    # Total findings across all scans for this tenant
    # Query findings through scans belonging to this tenant
    total_findings_stmt = (
        select(func.coalesce(func.sum(Scan.total_findings), 0))
        .where(Scan.tenant_id == tenant_id)
    )
    result = await db.execute(total_findings_stmt)
    total_findings = result.scalar() or 0

    # Critical findings
    critical_stmt = (
        select(func.coalesce(func.sum(Scan.critical_findings), 0))
        .where(Scan.tenant_id == tenant_id)
    )
    result = await db.execute(critical_stmt)
    critical_findings = result.scalar() or 0

    # High findings
    high_stmt = (
        select(func.coalesce(func.sum(Scan.high_findings), 0))
        .where(Scan.tenant_id == tenant_id)
    )
    result = await db.execute(high_stmt)
    high_findings = result.scalar() or 0

    # Scans today (use naive datetime to match DB column type)
    today_start = datetime.utcnow().replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    scans_today_stmt = (
        select(func.count())
        .select_from(Scan)
        .where(Scan.tenant_id == tenant_id)
        .where(Scan.created_at >= today_start)
    )
    result = await db.execute(scans_today_stmt)
    scans_today = result.scalar() or 0

    # Average scan duration
    avg_duration_stmt = (
        select(func.avg(Scan.duration_seconds))
        .where(Scan.tenant_id == tenant_id)
        .where(Scan.status == "completed")
        .where(Scan.duration_seconds.isnot(None))
    )
    result = await db.execute(avg_duration_stmt)
    avg_duration = result.scalar() or 0.0

    # Total deployments
    total_deployments = await deployment_repo.count(tenant_id=tenant_id)

    return DashboardStats(
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        scans_today=scans_today,
        avg_scan_duration=float(avg_duration),
        total_deployments=total_deployments,
    )


@router.get("/scans", response_model=list[DashboardScanItem])
async def list_dashboard_scans(
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    deployment_repo: DeploymentRepo,
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(20, ge=1, le=100, description="Max results"),
) -> list[DashboardScanItem]:
    """List scans for the dashboard."""
    filters: dict = {"tenant_id": tenant.tenant_id}
    if status:
        filters["status"] = status

    scans = await scan_repo.list(
        offset=0,
        limit=limit,
        order_by="created_at",
        order_desc=True,
        **filters,
    )

    # Batch-fetch deployment names for all scans
    deployment_ids = list({s.deployment_id for s in scans})
    deployment_names: dict[str, str] = {}
    for dep_id in deployment_ids:
        dep = await deployment_repo.get(dep_id)
        if dep:
            deployment_names[dep_id] = dep.name

    items = []
    for scan in scans:
        target = deployment_names.get(scan.deployment_id, scan.deployment_id)

        items.append(DashboardScanItem(
            scan_id=scan.id,
            status=scan.status,
            target=target,
            profile=scan.profile,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            duration_seconds=float(scan.duration_seconds or 0),
            findings_count=scan.total_findings,
            critical_count=scan.critical_findings,
            high_count=scan.high_findings,
            medium_count=scan.medium_findings,
            low_count=scan.low_findings,
        ))

    return items


@router.get("/scans/{scan_id}/findings", response_model=list[DashboardFinding])
async def get_dashboard_scan_findings(
    scan_id: str,
    tenant: CurrentTenantDep,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    severity: str | None = Query(None, description="Filter by severity"),
    category: str | None = Query(None, description="Filter by category"),
) -> list[DashboardFinding]:
    """Get findings for a scan (dashboard format)."""
    import json

    scan = await scan_repo.get(scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    filters: dict = {"scan_id": scan_id}
    if severity:
        filters["severity"] = severity
    if category:
        filters["category"] = category

    findings = await finding_repo.list(offset=0, limit=500, **filters)

    items = []
    for f in findings:
        meta_data = {}
        if f.meta:
            try:
                meta_data = json.loads(f.meta)
            except (json.JSONDecodeError, TypeError):
                pass

        items.append(DashboardFinding(
            id=f.id,
            title=f.title,
            severity=f.severity,
            category=f.category or "unknown",
            component=meta_data.get("component_name", "unknown"),
            file_path=f.file_path,
            line_number=f.line_number,
            description=f.description or "",
        ))

    return items


@router.get("/findings/{finding_id}", response_model=DashboardFindingDetail)
async def get_dashboard_finding_detail(
    finding_id: str,
    tenant: CurrentTenantDep,
    db: DBSession,
    scan_repo: ScanRepo,
    finding_repo: FindingRepo,
    deployment_repo: DeploymentRepo,
) -> DashboardFindingDetail:
    """Get full finding detail for the dashboard.

    Enriches finding data with remediation template content (guardrail
    examples, detailed steps) looked up by the finding's category.
    When the deployment has a detected environment, cloud-specific
    remediation templates are preferred over generic ones.
    """
    import json

    finding = await finding_repo.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify the finding belongs to a scan owned by this tenant
    scan = await scan_repo.get(finding.scan_id)
    if not scan or scan.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    meta_data = {}
    if finding.meta:
        try:
            meta_data = json.loads(finding.meta)
        except (json.JSONDecodeError, TypeError):
            pass

    # Enrich with remediation template data
    guardrail_examples: list[GuardrailExampleItem] = []
    code_fix_examples: list[CodeFixExampleItem] = []
    remediation_steps = meta_data.get("remediation_steps", [])
    estimated_effort = None

    if finding.category:
        try:
            from mass.storage.repositories.remediation import RemediationTemplateRepository
            remediation_repo = RemediationTemplateRepository(db)

            # Determine cloud provider from deployment metadata for
            # environment-aware remediation lookup
            cloud_subcategory = None
            try:
                deployment = await deployment_repo.get(scan.deployment_id)
                if deployment and deployment.meta:
                    deploy_meta = json.loads(deployment.meta)
                    env = deploy_meta.get("environment", {})
                    cloud = env.get("cloud_provider", "unknown")
                    if cloud not in ("unknown", "hybrid"):
                        cloud_subcategory = cloud
            except Exception:
                pass

            # Try cloud-specific template first, then fall back to generic
            template = await remediation_repo.get_by_category(
                finding.category, subcategory=cloud_subcategory
            )
            if template:
                # Use template steps if finding doesn't have its own
                if not remediation_steps and template.steps:
                    try:
                        remediation_steps = json.loads(template.steps)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Load guardrail examples from template
                if template.guardrail_examples:
                    try:
                        raw_examples = json.loads(template.guardrail_examples)
                        guardrail_examples = [
                            GuardrailExampleItem(**ex) for ex in raw_examples
                        ]
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Load code fix examples from template
                if template.code_examples:
                    try:
                        raw_code = json.loads(template.code_examples)
                        code_fix_examples = [
                            CodeFixExampleItem(**ex) for ex in raw_code
                        ]
                    except (json.JSONDecodeError, TypeError):
                        pass

                estimated_effort = template.estimated_effort
        except Exception:
            pass  # Graceful degradation if template lookup fails

    return DashboardFindingDetail(
        id=finding.id,
        title=finding.title,
        severity=finding.severity,
        status=finding.status,
        category=finding.category or "unknown",
        component=meta_data.get("component_name", "unknown"),
        file_path=finding.file_path,
        line_number=finding.line_number,
        code_snippet=finding.code_snippet,
        description=finding.description or "",
        evidence=finding.evidence,
        remediation=finding.remediation,
        remediation_steps=remediation_steps,
        guardrail_examples=guardrail_examples,
        code_fix_examples=code_fix_examples,
        references=finding.references,
        rule_id=finding.rule_id,
        cwe_id=finding.cwe_id,
        owasp_category=finding.owasp_category,
        mitre_technique=finding.mitre_technique,
        estimated_effort=estimated_effort,
        confidence_level=meta_data.get("confidence_level"),
        original_severity=meta_data.get("original_severity"),
    )


@router.get("/deployments/{deployment_id}/topology")
async def get_dashboard_topology(
    deployment_id: str,
    tenant: CurrentTenantDep,
    deployment_repo: DeploymentRepo,
) -> dict:
    """Get topology and environment for dashboard rendering."""
    import json as _json

    deployment = await deployment_repo.get(deployment_id)
    if not deployment or deployment.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Deployment not found")

    meta = {}
    if deployment.meta:
        try:
            meta = _json.loads(deployment.meta)
        except (ValueError, TypeError):
            pass

    topo = meta.get("topology", {"nodes": [], "edges": []})
    env = meta.get("environment", {})

    return {
        "deployment_id": deployment_id,
        "deployment_name": deployment.name,
        "topology": topo,
        "environment": env,
    }


@router.get("/ui", response_class=HTMLResponse)
async def dashboard_ui() -> HTMLResponse:
    """Serve the dashboard HTML UI.

    The UI fetches data from the dashboard API endpoints
    using the API key from the X-API-Key header.
    """
    from mass.dashboard.ui import DASHBOARD_HTML

    # Patch the API base URL to point to the main API's dashboard endpoints
    patched_html = DASHBOARD_HTML.replace(
        "const API = '/api';",
        "const API = '/api/v1/dashboard';",
    )

    # Add API key header injection to all fetch calls
    api_key_script = """
    <script>
        // Override fetch to include API key header
        const _originalFetch = window.fetch.bind(window);
        window.fetch = function(url, options) {
            if (!options) options = {};
            if (!options.headers) options.headers = {};

            // Get API key from URL param or localStorage
            const urlParams = new URLSearchParams(window.location.search);
            const apiKey = urlParams.get('api_key') || localStorage.getItem('mass_api_key') || '';

            if (apiKey) {
                localStorage.setItem('mass_api_key', apiKey);
                if (options.headers instanceof Headers) {
                    options.headers.set('X-API-Key', apiKey);
                } else {
                    options.headers['X-API-Key'] = apiKey;
                }
            }
            return _originalFetch(url, options);
        };

        // Show API key prompt if not set
        if (!localStorage.getItem('mass_api_key') && !new URLSearchParams(window.location.search).get('api_key')) {
            const key = prompt('Enter your MASS API key:');
            if (key) localStorage.setItem('mass_api_key', key);
        }
    </script>
    """

    # Inject API key script before the existing script tag
    patched_html = patched_html.replace(
        "<script>\n        const API",
        api_key_script + "\n    <script>\n        const API",
    )

    return HTMLResponse(content=patched_html)
