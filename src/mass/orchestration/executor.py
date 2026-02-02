"""Job executor module.

The JobExecutor runs individual scan jobs and collects results.
It manages timeouts, retries, and error handling.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Protocol
from uuid import uuid4

from mass.core.findings import Finding
from mass.core.types import Severity
from mass.orchestration.planner import JobType, PlannedJob


class JobStatus(str, Enum):
    """Job execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class JobResult:
    """Result of a job execution."""

    job_id: str
    job_type: JobType
    status: JobStatus = JobStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    # Results
    findings: list[Finding] = field(default_factory=list)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Metadata
    items_processed: int = 0
    items_total: int = 0
    error: str | None = None
    error_details: dict[str, Any] | None = None
    output: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update counts."""
        self.findings.append(finding)
        self.findings_count = len(self.findings)

        # Update severity counts
        if finding.severity == Severity.CRITICAL:
            self.critical_count += 1
        elif finding.severity == Severity.HIGH:
            self.high_count += 1
        elif finding.severity == Severity.MEDIUM:
            self.medium_count += 1
        elif finding.severity == Severity.LOW:
            self.low_count += 1
        else:
            self.info_count += 1

    def mark_started(self) -> None:
        """Mark job as started."""
        self.status = JobStatus.RUNNING
        self.started_at = datetime.utcnow()

    def mark_completed(self) -> None:
        """Mark job as completed."""
        self.status = JobStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = delta.total_seconds()

    def mark_failed(self, error: str, details: dict[str, Any] | None = None) -> None:
        """Mark job as failed."""
        self.status = JobStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error = error
        self.error_details = details
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = delta.total_seconds()

    def mark_timeout(self) -> None:
        """Mark job as timed out."""
        self.status = JobStatus.TIMEOUT
        self.completed_at = datetime.utcnow()
        self.error = "Job exceeded timeout"
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = delta.total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "job_type": self.job_type.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "items_processed": self.items_processed,
            "items_total": self.items_total,
            "error": self.error,
        }


class AnalyzerProtocol(Protocol):
    """Protocol for analyzer implementations."""

    async def analyze(self, context: dict[str, Any]) -> list[Finding]:
        """Run analysis and return findings."""
        ...


# Type alias for job handlers
JobHandler = Callable[[PlannedJob, dict[str, Any]], JobResult]


class JobExecutor:
    """Executes scan jobs and collects results.

    The executor manages individual job execution with
    timeout handling and error recovery.
    """

    def __init__(self) -> None:
        """Initialize the job executor."""
        self._handlers: dict[JobType, JobHandler] = {}
        self._results: dict[str, JobResult] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default job handlers."""
        # Each handler is registered for its job type
        self._handlers[JobType.DEPLOYMENT_SCAN] = self._handle_deployment_scan
        self._handlers[JobType.SECRET_DETECTION] = self._handle_secret_detection
        self._handlers[JobType.INFRASTRUCTURE_SCAN] = self._handle_infrastructure_scan
        self._handlers[JobType.MODEL_FILE_SCAN] = self._handle_model_file_scan
        self._handlers[JobType.CONTEXT_ANALYSIS] = self._handle_context_analysis
        self._handlers[JobType.MCP_ANALYSIS] = self._handle_mcp_analysis
        self._handlers[JobType.ATTACK_SURFACE] = self._handle_attack_surface
        self._handlers[JobType.WORKFLOW_ANALYSIS] = self._handle_workflow_analysis
        self._handlers[JobType.MODEL_INTERROGATION] = self._handle_model_interrogation

    def register_handler(self, job_type: JobType, handler: JobHandler) -> None:
        """Register a custom job handler.

        Args:
            job_type: Type of job to handle.
            handler: Handler function.
        """
        self._handlers[job_type] = handler

    def execute(
        self,
        job: PlannedJob,
        context: dict[str, Any],
    ) -> JobResult:
        """Execute a single job.

        Args:
            job: The job to execute.
            context: Execution context with paths, configs, etc.

        Returns:
            JobResult with findings and status.
        """
        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            handler = self._handlers.get(job.job_type)
            if handler is None:
                result.mark_failed(f"No handler for job type: {job.job_type}")
                return result

            # Execute the handler
            result = handler(job, context)

        except TimeoutError:
            result.mark_timeout()
        except Exception as e:
            result.mark_failed(str(e), {"exception_type": type(e).__name__})

        self._results[job.id] = result
        return result

    def get_result(self, job_id: str) -> JobResult | None:
        """Get result for a job.

        Args:
            job_id: Job ID.

        Returns:
            JobResult if found, None otherwise.
        """
        return self._results.get(job_id)

    def get_all_results(self) -> list[JobResult]:
        """Get all job results."""
        return list(self._results.values())

    def get_all_findings(self) -> list[Finding]:
        """Get findings from all completed jobs."""
        findings = []
        for result in self._results.values():
            if result.status == JobStatus.COMPLETED:
                findings.extend(result.findings)
        return findings

    # Default handlers (synchronous implementations)

    def _handle_deployment_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle deployment scanning job."""
        from mass.analyzers.deployment.scanner import DeploymentScanner

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            if not path:
                result.mark_completed()
                result.output["message"] = "No deployment path provided"
                return result

            scanner = DeploymentScanner()
            scan_result = scanner.scan(path)

            # Store discovered components in output
            result.output["manifest"] = scan_result.manifest.to_dict() if scan_result.manifest else None
            result.output["components_found"] = len(scan_result.components)

            # Add any findings from the scan
            for finding in scan_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_secret_detection(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle secret detection job."""
        from mass.analyzers.secrets.detector import SecretDetector

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            if not path:
                result.mark_completed()
                return result

            detector = SecretDetector()
            findings = detector.scan_directory(path)

            for finding in findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_infrastructure_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle infrastructure scanning job."""
        from mass.analyzers.infrastructure.scanner import InfrastructureScanner

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            if not path:
                result.mark_completed()
                return result

            scanner = InfrastructureScanner()
            scan_result = scanner.scan(path)

            for finding in scan_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_model_file_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle model file scanning job."""
        from mass.analyzers.model_file.scanner import ModelFileScanner

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = job.component_id or context.get("deployment_path")
            if not path:
                result.mark_completed()
                return result

            scanner = ModelFileScanner()
            scan_result = scanner.scan_path(path)

            for finding in scan_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_context_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle context analysis job."""
        from mass.analyzers.context.analyzer import ContextAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            content = context.get("context_content")
            if not content:
                result.mark_completed()
                return result

            analyzer = ContextAnalyzer()
            analysis_result = analyzer.analyze(content)

            for finding in analysis_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_mcp_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle MCP analysis job."""
        from mass.analyzers.mcp.analyzer import MCPAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            config = context.get("mcp_config")
            if not config:
                result.mark_completed()
                return result

            analyzer = MCPAnalyzer()
            analysis_result = analyzer.analyze(config)

            for finding in analysis_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_attack_surface(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle attack surface analysis job."""
        from mass.analyzers.attack_surface.analyzer import AttackSurfaceAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            components = context.get("components", [])
            if not components:
                result.mark_completed()
                return result

            analyzer = AttackSurfaceAnalyzer()
            analysis_result = analyzer.analyze(components)

            # Store attack surface data in output
            result.output["vectors"] = len(analysis_result.vectors)
            result.output["paths"] = len(analysis_result.vulnerability_paths)

            for finding in analysis_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_workflow_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle workflow analysis job."""
        from mass.analyzers.workflow.analyzer import WorkflowAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = job.component_id or context.get("workflow_file")
            if not path:
                result.mark_completed()
                return result

            analyzer = WorkflowAnalyzer()
            analysis_result = analyzer.analyze_file(path)

            for finding in analysis_result.findings:
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_model_interrogation(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle model interrogation job."""
        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            # Model interrogation requires model endpoint configuration
            endpoint = context.get("model_endpoint")
            if not endpoint:
                result.mark_completed()
                result.output["message"] = "No model endpoint configured"
                return result

            # TODO: Integrate with probes/detectors/runners
            # This would run the probe suite against the model
            result.output["message"] = "Model interrogation not yet implemented"
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result
