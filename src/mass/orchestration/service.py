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


def _target_type_suffix(target_type: str) -> str:
    """Return a reasonable file suffix for inline content by target type."""
    return {
        "mcp_server": ".json",
        "model_file": ".bin",
        "skill_file": ".py",
        "instruction_file": ".txt",
        "model_endpoint": ".txt",
        "agent_endpoint": ".txt",
    }.get(target_type, ".txt")


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
# Type for finding callbacks (incremental storage after each job)
FindingCallback = Callable[[list[Finding]], None]


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
        on_findings: FindingCallback | None = None,
    ) -> ScanResult:
        """Execute a scan plan.

        Args:
            scan_id: ID of the scan to execute.
            context: Execution context with deployment paths, configs, etc.
            on_progress: Optional callback for progress updates.
            on_findings: Optional callback for incremental finding storage.

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
            # Cross-job deduplication: track (file_path, line_number) to
            # prevent the same location being reported by multiple analyzers.
            seen_locations: dict[tuple, Finding] = {}

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

                        # Deduplicate findings across jobs by (file, line).
                        # Different analyzers (secrets, context, infra) can
                        # flag the same location; keep the highest severity.
                        unique_findings: list[Finding] = []
                        for f in job_result.findings:
                            loc_key = (
                                str(f.file_path or "").replace("\\", "/"),
                                f.line_number,
                            )
                            # Findings without a file/line are always unique
                            if not f.file_path and not f.line_number:
                                unique_findings.append(f)
                                continue

                            existing = seen_locations.get(loc_key)
                            if existing is None:
                                seen_locations[loc_key] = f
                                unique_findings.append(f)
                            else:
                                # Keep higher severity; on tie keep the one
                                # with more evidence content
                                sev_order = {
                                    Severity.CRITICAL: 4, Severity.HIGH: 3,
                                    Severity.MEDIUM: 2, Severity.LOW: 1,
                                    Severity.INFO: 0,
                                }
                                new_rank = sev_order.get(f.severity, 0)
                                old_rank = sev_order.get(existing.severity, 0)
                                if new_rank > old_rank:
                                    seen_locations[loc_key] = f
                                    # Replace in all_findings
                                    all_findings[:] = [
                                        x for x in all_findings
                                        if x is not existing
                                    ]
                                    unique_findings.append(f)

                        all_findings.extend(unique_findings)
                        # Store findings incrementally via callback
                        if on_findings and unique_findings:
                            try:
                                on_findings(unique_findings)
                            except Exception:
                                pass  # Don't fail scan on storage error
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

            # Capture environment + topology from discovery phase
            if context.get("_environment"):
                result.metadata["environment"] = context["_environment"]
            if context.get("_topology"):
                result.metadata["topology"] = context["_topology"]

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

    # Directories to exclude from recursive scanning.
    # These contain build artifacts, compiled code, or vendored dependencies
    # that are not relevant to AI security analysis.
    # TODO: Replace with Discovery API (P0 future enhancement) for intelligent
    #       component discovery across local, AWS, Azure, and GCP environments
    EXCLUDED_DIRS = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
        ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "build", "dist", "eggs",
        # Native/compiled model runtimes (not the model files themselves)
        "llama.cpp", "sd.cpp", "whisper.cpp",
        # Binary/compiled output
        "bin", "obj", "target", "out",
        # Vendored/downloaded dependencies
        "vendor", "third_party", "external",
        # Large framework directories
        "framepack_cu126_torch26",
    }

    def _walk_files(self, root_path: str) -> list[str]:
        """Walk directory tree, pruning excluded directories.

        Uses os.walk with topdown=True to skip entire subtrees,
        avoiding the performance issue of rglob traversing 50K+ files.

        Args:
            root_path: Root directory to walk.

        Returns:
            List of relative file paths (using forward slashes).
        """
        import os

        files = []
        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            # Prune excluded directories IN PLACE so os.walk skips them
            dirnames[:] = [
                d for d in dirnames
                if d not in self.EXCLUDED_DIRS and not d.endswith(".egg-info")
            ]
            rel_dir = os.path.relpath(dirpath, root_path)
            for filename in filenames:
                if rel_dir == ".":
                    files.append(filename)
                else:
                    files.append(f"{rel_dir}/{filename}".replace("\\", "/"))
        return files

    def _has_matching_files(self, file_list: list[str], *patterns: str) -> bool:
        """Check if any files match the given patterns.

        Args:
            file_list: Pre-collected list of relative file paths.
            *patterns: Glob-like patterns to check (simple substring/suffix match).

        Returns:
            True if any file matches any pattern.
        """
        import fnmatch

        for filepath in file_list:
            filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
            for pattern in patterns:
                if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                    return True
        return False

    def scan_deployment(
        self,
        deployment_path: str,
        profile_name: str = "standard",
        deployment_name: str | None = None,
        on_progress: ProgressCallback | None = None,
        on_findings: FindingCallback | None = None,
        model_endpoint: str | None = None,
        model_provider: str | None = None,
        model_name: str | None = None,
        model_api_key: str | None = None,
        system_prompt: str | None = None,
        remediation_cache: Any | None = None,
        target_type: str = "deployment",
        target_files: list[str] | None = None,
        inline_content: str | None = None,
        agent_meta: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Scan a deployment or individual target.

        Args:
            deployment_path: Path to deployment directory or file.
            profile_name: Scan profile name.
            deployment_name: Optional deployment name.
            on_progress: Optional progress callback.
            model_endpoint: Model API endpoint for dynamic analysis.
            model_provider: Model provider (openai, anthropic, ollama, bedrock,
                azure_openai, gemini, grok, etc.).
            model_name: Model identifier.
            model_api_key: API key for model provider.
            system_prompt: System prompt to test with.
            target_type: Target type - deployment, mcp_server, model_file,
                skill_file, instruction_file, model_endpoint, agent_endpoint.
            target_files: Specific file paths to scan (for single targets).
            inline_content: Inline content for targets supplied directly.
            agent_meta: Agent-to-agent metadata (agent_url, agent_protocol,
                upstream_agents, downstream_agents, etc.).

        Returns:
            ScanResult with all findings.
        """
        from pathlib import Path

        # Branch on target type for discovery and planning
        if target_type == "deployment":
            # Full directory scan (original behavior)
            return self._scan_directory(
                deployment_path, profile_name, deployment_name,
                on_progress, on_findings, model_endpoint, model_provider,
                model_name, model_api_key, system_prompt, remediation_cache,
            )
        else:
            # Single-target scan (focused plan)
            return self._scan_single_target(
                deployment_path, target_type, target_files, inline_content,
                profile_name, deployment_name, on_progress, on_findings,
                model_endpoint, model_provider, model_name, model_api_key,
                system_prompt, remediation_cache, agent_meta,
            )

    def _scan_directory(
        self,
        deployment_path: str,
        profile_name: str,
        deployment_name: str | None,
        on_progress: ProgressCallback | None,
        on_findings: FindingCallback | None,
        model_endpoint: str | None,
        model_provider: str | None,
        model_name: str | None,
        model_api_key: str | None,
        system_prompt: str | None,
        remediation_cache: Any | None,
    ) -> ScanResult:
        """Full directory-based scan (original behavior)."""
        from pathlib import Path

        path = Path(deployment_path)
        if not path.exists():
            raise ValueError(f"Deployment path not found: {deployment_path}")

        # Walk directory once, pruning excluded dirs (fast: skips llama.cpp etc.)
        all_files = self._walk_files(str(path))

        # Discover components from the file list
        deployment = DeploymentInfo(
            id=str(uuid4()),
            name=deployment_name or path.name,
            path=str(path),
            has_models=self._has_matching_files(
                all_files, "*.pt", "*.gguf", "*.safetensors", "*.bin",
            ),
            has_context=self._has_matching_files(
                all_files, "*prompt*", "*context*", "*config*.json",
            ),
            has_mcp_servers=self._has_matching_files(all_files, "*mcp*"),
            has_workflows=self._has_matching_files(
                all_files, "*agent*", "*workflow*", "*plan*",
            ),
            has_infrastructure=self._has_matching_files(
                all_files, "Dockerfile", "docker-compose*", "*.yaml", "*.tf",
            ),
            has_secrets_risk=True,
            has_model_endpoint=bool(model_endpoint),
        )

        plan = self.create_scan(deployment, profile_name)
        context: dict = {
            "deployment_path": str(path),
            "file_index": all_files,
        }

        if model_endpoint:
            context["model_endpoint"] = model_endpoint
        if model_provider:
            context["model_provider"] = model_provider
        if model_name:
            context["model_name"] = model_name
        if model_api_key:
            context["model_api_key"] = model_api_key
        if system_prompt:
            context["system_prompt"] = system_prompt

        if remediation_cache is not None:
            from mass.orchestration.remediation_resolver import REMEDIATION_CACHE_KEY
            context[REMEDIATION_CACHE_KEY] = remediation_cache

        return self.run_scan(plan.scan_id, context, on_progress, on_findings)

    def _scan_single_target(
        self,
        deployment_path: str | None,
        target_type: str,
        target_files: list[str] | None,
        inline_content: str | None,
        profile_name: str,
        deployment_name: str | None,
        on_progress: ProgressCallback | None,
        on_findings: FindingCallback | None,
        model_endpoint: str | None,
        model_provider: str | None,
        model_name: str | None,
        model_api_key: str | None,
        system_prompt: str | None,
        remediation_cache: Any | None,
        agent_meta: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Focused scan for a single target type.

        Skips full directory walk and deployment discovery. Creates a
        targeted DeploymentInfo with only the relevant component flags
        set, so the planner generates a focused plan.
        """
        from pathlib import Path
        import tempfile
        import os

        # Resolve file list for single-target scanning
        all_files: list[str] = []
        base_path = deployment_path or ""

        if target_files:
            all_files = list(target_files)
        elif deployment_path:
            p = Path(deployment_path)
            if p.is_file():
                all_files = [p.name]
                base_path = str(p.parent)
            elif p.is_dir():
                all_files = self._walk_files(str(p))

        # For inline content, write to a temp file so analyzers can process it
        temp_file_path: str | None = None
        if inline_content and not all_files:
            suffix = _target_type_suffix(target_type)
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, dir=base_path or None,
                delete=False, prefix="mass_inline_",
            ) as tmp:
                tmp.write(inline_content)
                temp_file_path = tmp.name

            base_path = os.path.dirname(temp_file_path)
            all_files = [os.path.basename(temp_file_path)]

        # Build focused DeploymentInfo based on target_type
        # agent_endpoint enables both model probing and context analysis
        # to test agent-to-agent delegation, injection propagation, and
        # confused deputy attacks
        deployment = DeploymentInfo(
            id=str(uuid4()),
            name=deployment_name or f"{target_type}-target",
            path=base_path or None,
            has_models=(target_type == "model_file"),
            has_context=(target_type in ("skill_file", "instruction_file", "agent_endpoint")),
            has_mcp_servers=(target_type == "mcp_server"),
            has_workflows=(target_type in ("skill_file", "agent_endpoint")),
            has_infrastructure=False,
            has_secrets_risk=(target_type in ("skill_file", "mcp_server", "deployment", "agent_endpoint")),
            has_model_endpoint=(
                target_type in ("model_endpoint", "agent_endpoint")
                and bool(model_endpoint)
            ),
        )

        plan = self.create_scan(deployment, profile_name)

        context: dict = {
            "deployment_path": base_path,
            "file_index": all_files,
            "target_type": target_type,
        }
        if target_files:
            context["target_files"] = target_files
        if inline_content:
            context["inline_content"] = inline_content
        if temp_file_path:
            context["_temp_files"] = [temp_file_path]

        if model_endpoint:
            context["model_endpoint"] = model_endpoint
        if model_provider:
            context["model_provider"] = model_provider
        if model_name:
            context["model_name"] = model_name
        if model_api_key:
            context["model_api_key"] = model_api_key
        if system_prompt:
            context["system_prompt"] = system_prompt

        # Inject agent-to-agent metadata for agent_endpoint targets
        if agent_meta:
            if agent_meta.get("agent_url"):
                context["agent_url"] = agent_meta["agent_url"]
            if agent_meta.get("agent_protocol"):
                context["agent_protocol"] = agent_meta["agent_protocol"]
            if agent_meta.get("upstream_agents"):
                context["upstream_agents"] = agent_meta["upstream_agents"]
            if agent_meta.get("downstream_agents"):
                context["downstream_agents"] = agent_meta["downstream_agents"]

        if remediation_cache is not None:
            from mass.orchestration.remediation_resolver import REMEDIATION_CACHE_KEY
            context[REMEDIATION_CACHE_KEY] = remediation_cache

        try:
            result = self.run_scan(
                plan.scan_id, context, on_progress, on_findings,
            )
        finally:
            # Clean up temp files
            if temp_file_path:
                try:
                    os.unlink(temp_file_path)
                except OSError:
                    pass

        return result
