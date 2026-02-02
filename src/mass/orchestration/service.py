"""Scan service module.

The ScanService is the main orchestrator that manages
the complete scan lifecycle from creation to completion.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from mass.core.findings import Finding, FindingSummary
from mass.core.types import ScanStatus, Severity
from mass.orchestration.executor import JobExecutor, JobResult, JobStatus
from mass.orchestration.planner import (
    DeploymentInfo,
    PlannedJob,
    ScanPlan,
    ScanPlanner,
)
from mass.orchestration.profiles import ScanProfile, get_profile


@dataclass
class ScanServiceConfig:
    """Configuration for the scan service."""

    max_concurrent_scans: int = 10
    default_profile: str = "standard"
    results_ttl_hours: int = 24
    enable_caching: bool = True


@dataclass
class ScanProgress:
    """Progress information for a scan."""

    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    progress_percent: float = 0.0
    current_phase: str = ""
    message: str = ""

    jobs_total: int = 0
    jobs_completed: int = 0
    jobs_failed: int = 0

    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0

    started_at: datetime | None = None
    estimated_completion: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "progress_percent": self.progress_percent,
            "current_phase": self.current_phase,
            "message": self.message,
            "jobs_total": self.jobs_total,
            "jobs_completed": self.jobs_completed,
            "jobs_failed": self.jobs_failed,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }


@dataclass
class ScanResult:
    """Complete scan result."""

    scan_id: str
    deployment_id: str
    profile_name: str

    status: ScanStatus = ScanStatus.COMPLETED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    # Results
    findings: list[Finding] = field(default_factory=list)
    summary: FindingSummary | None = None

    # Job results
    job_results: list[JobResult] = field(default_factory=list)
    jobs_completed: int = 0
    jobs_failed: int = 0

    # Metadata
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "deployment_id": self.deployment_id,
            "profile_name": self.profile_name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": len(self.findings),
            "summary": {
                "total": self.summary.total if self.summary else 0,
                "critical": self.summary.critical_count if self.summary else 0,
                "high": self.summary.high_count if self.summary else 0,
                "medium": self.summary.medium_count if self.summary else 0,
                "low": self.summary.low_count if self.summary else 0,
                "info": self.summary.info_count if self.summary else 0,
            },
            "jobs_completed": self.jobs_completed,
            "jobs_failed": self.jobs_failed,
            "error": self.error,
        }


# Type for progress callbacks
ProgressCallback = Callable[[ScanProgress], None]


class ScanService:
    """Main scan orchestration service.

    The ScanService manages the complete lifecycle of security scans:
    - Creating scan plans based on deployment and profile
    - Executing jobs with proper ordering and parallelism
    - Collecting and aggregating results
    - Managing scan state and progress
    """

    def __init__(self, config: ScanServiceConfig | None = None) -> None:
        """Initialize the scan service.

        Args:
            config: Service configuration.
        """
        self.config = config or ScanServiceConfig()
        self._executor = JobExecutor()
        self._scans: dict[str, ScanPlan] = {}
        self._results: dict[str, ScanResult] = {}
        self._progress: dict[str, ScanProgress] = {}
        self._callbacks: dict[str, list[ProgressCallback]] = {}

    def create_scan(
        self,
        deployment: DeploymentInfo,
        profile_name: str | None = None,
        scan_id: str | None = None,
    ) -> ScanPlan:
        """Create a new scan plan.

        Args:
            deployment: Deployment to scan.
            profile_name: Scan profile name.
            scan_id: Optional scan ID (generated if not provided).

        Returns:
            ScanPlan ready for execution.
        """
        scan_id = scan_id or str(uuid4())
        profile_name = profile_name or self.config.default_profile
        profile = get_profile(profile_name)

        planner = ScanPlanner(profile)
        plan = planner.create_plan(scan_id, deployment)

        self._scans[scan_id] = plan
        self._progress[scan_id] = ScanProgress(
            scan_id=scan_id,
            jobs_total=plan.total_jobs,
        )

        return plan

    def run_scan(
        self,
        scan_id: str,
        context: dict[str, Any],
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Execute a scan plan.

        Args:
            scan_id: ID of the scan to execute.
            context: Execution context with deployment paths, configs, etc.
            on_progress: Optional callback for progress updates.

        Returns:
            ScanResult with all findings.
        """
        plan = self._scans.get(scan_id)
        if not plan:
            raise ValueError(f"Scan not found: {scan_id}")

        progress = self._progress[scan_id]
        progress.status = ScanStatus.RUNNING
        progress.started_at = datetime.utcnow()
        progress.message = "Starting scan"

        if on_progress:
            if scan_id not in self._callbacks:
                self._callbacks[scan_id] = []
            self._callbacks[scan_id].append(on_progress)

        # Initialize result
        result = ScanResult(
            scan_id=scan_id,
            deployment_id=plan.deployment_id,
            profile_name=plan.profile_name,
            status=ScanStatus.RUNNING,
            started_at=progress.started_at,
        )

        try:
            # Execute jobs
            completed_jobs: set[str] = set()
            all_findings: list[Finding] = []

            while True:
                ready_jobs = plan.get_ready_jobs(completed_jobs)
                if not ready_jobs:
                    break

                for job in ready_jobs:
                    # Update progress
                    progress.current_phase = job.job_type.value
                    progress.message = f"Running: {job.name}"
                    self._notify_progress(scan_id)

                    # Execute job
                    job_result = self._executor.execute(job, context)
                    result.job_results.append(job_result)

                    # Update counts
                    if job_result.status == JobStatus.COMPLETED:
                        completed_jobs.add(job.id)
                        result.jobs_completed += 1
                        all_findings.extend(job_result.findings)
                    else:
                        result.jobs_failed += 1
                        if job_result.status == JobStatus.FAILED:
                            completed_jobs.add(job.id)  # Mark as done even if failed

                    # Update progress
                    progress.jobs_completed = result.jobs_completed
                    progress.jobs_failed = result.jobs_failed
                    progress.progress_percent = (
                        len(completed_jobs) / plan.total_jobs * 100
                        if plan.total_jobs > 0
                        else 100
                    )
                    progress.findings_count = len(all_findings)
                    progress.critical_count = sum(
                        1 for f in all_findings if f.severity == Severity.CRITICAL
                    )
                    progress.high_count = sum(
                        1 for f in all_findings if f.severity == Severity.HIGH
                    )
                    self._notify_progress(scan_id)

            # Finalize result
            result.findings = all_findings
            result.summary = FindingSummary.from_findings(all_findings)
            result.status = ScanStatus.COMPLETED
            result.completed_at = datetime.utcnow()
            if result.started_at:
                result.duration_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()

            # Update progress
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100.0
            progress.message = "Scan completed"
            self._notify_progress(scan_id)

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error = str(e)
            result.completed_at = datetime.utcnow()

            progress.status = ScanStatus.FAILED
            progress.message = f"Scan failed: {e}"
            self._notify_progress(scan_id)

        self._results[scan_id] = result
        return result

    def get_progress(self, scan_id: str) -> ScanProgress | None:
        """Get current scan progress.

        Args:
            scan_id: Scan ID.

        Returns:
            ScanProgress if found.
        """
        return self._progress.get(scan_id)

    def get_result(self, scan_id: str) -> ScanResult | None:
        """Get scan result.

        Args:
            scan_id: Scan ID.

        Returns:
            ScanResult if scan is complete.
        """
        return self._results.get(scan_id)

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan.

        Args:
            scan_id: Scan ID.

        Returns:
            True if cancelled, False if not found or not running.
        """
        progress = self._progress.get(scan_id)
        if not progress or progress.status != ScanStatus.RUNNING:
            return False

        progress.status = ScanStatus.CANCELLED
        progress.message = "Scan cancelled by user"
        self._notify_progress(scan_id)

        if scan_id in self._results:
            self._results[scan_id].status = ScanStatus.CANCELLED

        return True

    def _notify_progress(self, scan_id: str) -> None:
        """Notify progress callbacks."""
        progress = self._progress.get(scan_id)
        callbacks = self._callbacks.get(scan_id, [])

        if progress:
            for callback in callbacks:
                try:
                    callback(progress)
                except Exception:
                    pass  # Ignore callback errors

    def scan_deployment(
        self,
        deployment_path: str,
        profile_name: str = "standard",
        deployment_name: str | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Convenience method to scan a deployment path.

        Args:
            deployment_path: Path to deployment directory.
            profile_name: Scan profile name.
            deployment_name: Optional deployment name.
            on_progress: Optional progress callback.

        Returns:
            ScanResult with all findings.
        """
        from pathlib import Path

        path = Path(deployment_path)
        if not path.exists():
            raise ValueError(f"Deployment path not found: {deployment_path}")

        # Create deployment info from path
        deployment = DeploymentInfo(
            id=str(uuid4()),
            name=deployment_name or path.name,
            path=str(path),
            has_models=any(path.rglob("*.pt")) or any(path.rglob("*.gguf")),
            has_context=any(path.rglob("*prompt*")) or any(path.rglob("*context*")),
            has_mcp_servers=any(path.rglob("*mcp*")),
            has_workflows=any(path.rglob("*agent*")) or any(path.rglob("*workflow*")),
            has_infrastructure=any(path.rglob("Dockerfile"))
            or any(path.rglob("*.yaml"))
            or any(path.rglob("*.tf")),
            has_secrets_risk=True,
        )

        # Create and run scan
        plan = self.create_scan(deployment, profile_name)
        context = {"deployment_path": str(path)}
        return self.run_scan(plan.scan_id, context, on_progress)
