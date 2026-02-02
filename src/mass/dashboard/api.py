"""REST API endpoints for the dashboard.

Provides endpoints for scan management, results retrieval,
and analytics data.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field


router = APIRouter(tags=["api"])


# Request/Response Models

class ScanRequest(BaseModel):
    """Request to start a scan."""

    target: str = Field(..., description="Path to scan")
    name: str | None = Field(None, description="Scan name")
    profile: str = Field("standard", description="Scan profile")


class ScanResponse(BaseModel):
    """Response for scan operations."""

    scan_id: str
    status: str
    message: str


class FindingResponse(BaseModel):
    """Response containing a finding."""

    id: str
    title: str
    severity: str
    category: str
    component: str
    file_path: str | None = None
    line_number: int | None = None
    description: str = ""


class ScanResultResponse(BaseModel):
    """Response containing scan results."""

    scan_id: str
    status: str
    target: str
    profile: str
    started_at: str
    completed_at: str | None = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


class StatsResponse(BaseModel):
    """Response containing dashboard statistics."""

    total_scans: int = 0
    active_scans: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    scans_today: int = 0
    avg_scan_duration: float = 0.0


# API Endpoints

@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "mass-dashboard"}


@router.get("/stats", response_model=StatsResponse)
async def get_stats(request: Request) -> StatsResponse:
    """Get dashboard statistics."""
    store = request.app.state.scan_store
    scans = list(store.values())

    total_findings = 0
    critical_findings = 0
    active_scans = 0
    total_duration = 0.0
    completed_count = 0
    today = datetime.utcnow().date()
    scans_today = 0

    for scan in scans:
        if scan.get("status") == "running":
            active_scans += 1
        if scan.get("status") == "completed":
            completed_count += 1
            total_duration += scan.get("duration_seconds", 0)

        findings = scan.get("findings", [])
        total_findings += len(findings)
        critical_findings += sum(1 for f in findings if f.get("severity") == "critical")

        started = scan.get("started_at")
        if started and isinstance(started, datetime) and started.date() == today:
            scans_today += 1

    return StatsResponse(
        total_scans=len(scans),
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        scans_today=scans_today,
        avg_scan_duration=total_duration / completed_count if completed_count > 0 else 0,
    )


@router.post("/scans", response_model=ScanResponse)
async def start_scan(request: Request, scan_request: ScanRequest) -> ScanResponse:
    """Start a new scan."""
    from pathlib import Path

    target_path = Path(scan_request.target)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Target not found: {scan_request.target}")

    scan_id = str(uuid4())

    # Store scan info
    scan_data = {
        "scan_id": scan_id,
        "status": "pending",
        "target": scan_request.target,
        "name": scan_request.name or target_path.name,
        "profile": scan_request.profile,
        "started_at": datetime.utcnow(),
        "findings": [],
    }
    request.app.state.scan_store[scan_id] = scan_data

    # Start async scan in background
    import asyncio
    asyncio.create_task(_run_scan(request.app, scan_id, scan_request))

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scan started for {scan_request.target}",
    )


async def _run_scan(app: Any, scan_id: str, scan_request: ScanRequest) -> None:
    """Run scan in background."""
    store = app.state.scan_store

    try:
        store[scan_id]["status"] = "running"

        # Use SDK to run scan
        from mass.sdk import MASS, ScanProfile

        profile_map = {
            "quick": ScanProfile.QUICK,
            "standard": ScanProfile.STANDARD,
            "comprehensive": ScanProfile.COMPREHENSIVE,
        }
        profile = profile_map.get(scan_request.profile, ScanProfile.STANDARD)

        client = MASS()
        result = client.scan(scan_request.target, profile=profile)

        # Update store with results
        store[scan_id].update({
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "duration_seconds": result.duration_seconds,
            "findings": [f.to_dict() for f in result.findings],
            "summary": result.summary.to_dict(),
        })

    except Exception as e:
        store[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow(),
        })


@router.get("/scans", response_model=list[ScanResultResponse])
async def list_scans(
    request: Request,
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
) -> list[ScanResultResponse]:
    """List all scans."""
    store = request.app.state.scan_store
    scans = list(store.values())

    # Filter by status
    if status:
        scans = [s for s in scans if s.get("status") == status]

    # Sort by start time (newest first)
    scans.sort(key=lambda s: s.get("started_at", datetime.min), reverse=True)

    # Limit results
    scans = scans[:limit]

    return [_scan_to_response(s) for s in scans]


@router.get("/scans/{scan_id}", response_model=ScanResultResponse)
async def get_scan(request: Request, scan_id: str) -> ScanResultResponse:
    """Get scan by ID."""
    store = request.app.state.scan_store

    if scan_id not in store:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    return _scan_to_response(store[scan_id])


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def get_scan_findings(
    request: Request,
    scan_id: str,
    severity: str | None = Query(None, description="Filter by severity"),
    category: str | None = Query(None, description="Filter by category"),
) -> list[FindingResponse]:
    """Get findings for a scan."""
    store = request.app.state.scan_store

    if scan_id not in store:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    findings = store[scan_id].get("findings", [])

    # Filter
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.lower()]
    if category:
        findings = [f for f in findings if f.get("category") == category.lower()]

    return [FindingResponse(**f) for f in findings]


@router.delete("/scans/{scan_id}")
async def cancel_scan(request: Request, scan_id: str) -> ScanResponse:
    """Cancel a scan."""
    store = request.app.state.scan_store

    if scan_id not in store:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    scan = store[scan_id]
    if scan.get("status") in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail="Scan already finished")

    scan["status"] = "cancelled"
    scan["completed_at"] = datetime.utcnow()

    return ScanResponse(
        scan_id=scan_id,
        status="cancelled",
        message="Scan cancelled",
    )


def _scan_to_response(scan: dict[str, Any]) -> ScanResultResponse:
    """Convert internal scan to response."""
    findings = scan.get("findings", [])

    return ScanResultResponse(
        scan_id=scan.get("scan_id", ""),
        status=scan.get("status", "unknown"),
        target=scan.get("target", ""),
        profile=scan.get("profile", "standard"),
        started_at=scan.get("started_at", datetime.utcnow()).isoformat() if scan.get("started_at") else "",
        completed_at=scan.get("completed_at").isoformat() if scan.get("completed_at") else None,
        duration_seconds=scan.get("duration_seconds", 0.0),
        findings_count=len(findings),
        critical_count=sum(1 for f in findings if f.get("severity") == "critical"),
        high_count=sum(1 for f in findings if f.get("severity") == "high"),
        medium_count=sum(1 for f in findings if f.get("severity") == "medium"),
        low_count=sum(1 for f in findings if f.get("severity") == "low"),
        info_count=sum(1 for f in findings if f.get("severity") == "info"),
    )
