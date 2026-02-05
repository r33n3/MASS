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
        """Get deduplicated findings from all completed jobs.

        Applies cross-job deduplication by (file_path, line_number),
        keeping the highest-severity finding per location.
        """
        all_findings: list[Finding] = []
        seen: dict[tuple, Finding] = {}
        sev_order = {
            Severity.CRITICAL: 4, Severity.HIGH: 3,
            Severity.MEDIUM: 2, Severity.LOW: 1,
            Severity.INFO: 0,
        }

        for result in self._results.values():
            if result.status == JobStatus.COMPLETED:
                for f in result.findings:
                    if not f.file_path and not f.line_number:
                        all_findings.append(f)
                        continue

                    loc_key = (
                        str(f.file_path or "").replace("\\", "/"),
                        f.line_number,
                    )
                    existing = seen.get(loc_key)
                    if existing is None:
                        seen[loc_key] = f
                        all_findings.append(f)
                    elif sev_order.get(f.severity, 0) > sev_order.get(existing.severity, 0):
                        seen[loc_key] = f
                        all_findings[:] = [x for x in all_findings if x is not existing]
                        all_findings.append(f)

        return all_findings

    # --- Finding conversion helpers ---
    # Each analyzer returns its own finding type. These helpers convert
    # analyzer-specific findings to core Finding objects for aggregation.

    @staticmethod
    def _convert_secret_match(match: Any, environment: dict | None = None) -> Finding:
        """Convert SecretMatch to core Finding.

        When ``environment`` is provided, remediation guidance is tailored
        to the detected cloud provider (e.g., AWS Secrets Manager, Azure
        Key Vault, GCP Secret Manager).
        """
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType

        # Determine the appropriate secrets manager name
        cloud = (environment or {}).get("cloud_provider", "unknown")
        secrets_mgr_names = {
            "aws": "AWS Secrets Manager",
            "azure": "Azure Key Vault",
            "gcp": "Google Cloud Secret Manager",
        }
        secrets_mgr = secrets_mgr_names.get(cloud, "a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)")

        file_str = str(match.file_path) if match.file_path else ""
        file_name = file_str.rsplit("/", 1)[-1] if "/" in file_str else file_str
        masked = getattr(match, "masked_value", None) or "***"
        is_config = any(
            file_str.endswith(ext)
            for ext in (".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".json", ".env")
        )

        # Build a specific description that tells the user exactly what was found
        location_str = f"in `{file_name}` at line {match.line_number}" if file_name and match.line_number else ""
        if is_config:
            title = f"Hardcoded Secret in Config: {match.pattern_name}"
            description = (
                f"A {match.description.lower().rstrip('.')} pattern was detected "
                f"{location_str}. The matched value is: `{masked}`.\n\n"
                f"This configuration file contains what appears to be a hardcoded credential. "
                f"Use environment variables or {secrets_mgr} instead of embedding "
                f"secrets directly in configuration files."
            )
            remediation_summary = (
                f"Replace hardcoded credential with an environment variable reference "
                f"or {secrets_mgr} lookup"
            )
            remediation_steps = [
                "Replace the hardcoded value with an environment variable reference (e.g., ${API_KEY})",
                "If the credential is real, rotate it immediately",
                f"Configure your deployment to inject secrets via environment variables or {secrets_mgr}",
                "Add this config file pattern to .gitignore if it contains real credentials",
                "Consider using a .env.example file with placeholder values for documentation",
            ]
        else:
            title = f"Secret Detected: {match.pattern_name}"
            description = (
                f"A {match.description.lower().rstrip('.')} pattern was detected "
                f"{location_str}. The matched value is: `{masked}`.\n\n"
                f"Hardcoded credentials in source code can be extracted by anyone with "
                f"repository access. Move secrets to environment variables or {secrets_mgr}."
            )
            remediation_summary = f"Remove hardcoded secret and use environment variables or {secrets_mgr}"
            remediation_steps = [
                "Remove the secret from source code",
                "Rotate the compromised credential immediately",
                f"Use environment variables or {secrets_mgr}",
                "Add the file pattern to .gitignore if applicable",
            ]

        # Build evidence: primary = matched secret, secondary = code context
        evidence_items: list[Evidence] = []

        # Primary evidence: the matched secret value (masked)
        evidence_items.append(Evidence(
            type="secret_match",
            content=f"Pattern: {match.pattern_name}\nMatched: {masked}",
            source_file=file_str or None,
            source_line=match.line_number,
            metadata={
                "pattern_name": match.pattern_name,
                "category": str(match.category.value) if hasattr(match.category, 'value') else str(match.category),
                "entropy": round(match.entropy, 2) if getattr(match, "entropy", None) else None,
                "confidence": match.confidence,
            },
        ))

        # Secondary evidence: the surrounding line for context
        line_content = getattr(match, "line_content", None)
        if line_content and line_content.strip():
            evidence_items.append(Evidence(
                type="code",
                content=line_content.strip(),
                source_file=file_str or None,
                source_line=match.line_number,
            ))

        return Finding(
            title=title,
            description=description,
            severity=match.severity,
            category=AttackCategory.SECRETS_EXPOSURE,
            component_type=ComponentType.CONFIG,
            component_name=match.pattern_name,
            file_path=file_str or None,
            line_number=match.line_number,
            confidence=match.confidence,
            evidence=evidence_items,
            remediation=Remediation(
                summary=remediation_summary,
                steps=remediation_steps,
                references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
            ),
            cwe_ids=["CWE-798"],
            owasp_ids=["LLM06"],
            tags=[str(match.category.value) if hasattr(match.category, 'value') else str(match.category)],
            metadata={
                "confidence_level": "heuristic",
            },
        )

    @staticmethod
    def _convert_model_file_finding(mf_finding: Any, file_path: str | None = None) -> Finding:
        """Convert ModelFileFinding to core Finding."""
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType

        return Finding(
            title=mf_finding.title,
            description=mf_finding.description,
            severity=mf_finding.severity,
            category=AttackCategory.SUPPLY_CHAIN,
            component_type=ComponentType.MODEL,
            component_name=str(mf_finding.file_path.name) if mf_finding.file_path else "unknown",
            file_path=str(mf_finding.file_path) if mf_finding.file_path else file_path,
            evidence=[Evidence(
                type="config",
                content=str(mf_finding.evidence) if mf_finding.evidence else mf_finding.description,
                source_file=str(mf_finding.file_path) if mf_finding.file_path else None,
            )] if mf_finding.evidence else [],
            remediation=Remediation(
                summary=mf_finding.remediation or "Review model file for security issues",
                steps=["Verify model file integrity", "Check model provenance and supply chain"],
            ) if mf_finding.remediation else None,
            cwe_ids=["CWE-502"],
            tags=[str(mf_finding.category.value) if hasattr(mf_finding.category, 'value') else str(mf_finding.category)],
        )

    @staticmethod
    def _downgrade_severity(severity: "Severity") -> "Severity":
        """Downgrade severity by one level for unvalidated static findings."""
        from mass.core.types import Severity

        _map = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }
        return _map.get(severity, severity)

    @staticmethod
    def _convert_context_finding(ctx_finding: Any) -> Finding:
        """Convert ContextFinding to core Finding.

        Static pattern matches are downgraded one severity level and
        tagged with confidence_level=static_match to distinguish them
        from findings validated via model interaction.
        """
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType, ConfidenceLevel

        downgraded = JobExecutor._downgrade_severity(ctx_finding.severity)

        # Map context risk categories to OWASP LLM attack categories
        _CTX_CATEGORY = {
            "prompt_injection": (AttackCategory.PROMPT_INJECTION, ["LLM01"]),
            "jailbreak": (AttackCategory.JAILBREAK, ["LLM01"]),
            "data_exfiltration": (AttackCategory.DATA_LEAKAGE, ["LLM02"]),
            "privilege_escalation": (AttackCategory.EXCESSIVE_AGENCY, ["LLM06"]),
            "unsafe_execution": (AttackCategory.EXCESSIVE_AGENCY, ["LLM06"]),
            "information_disclosure": (AttackCategory.SYSTEM_PROMPT_LEAKAGE, ["LLM07"]),
            "policy_violation": (AttackCategory.IMPROPER_OUTPUT, ["LLM05"]),
            "deceptive_behavior": (AttackCategory.MISINFORMATION, ["LLM09"]),
            "resource_abuse": (AttackCategory.UNBOUNDED_CONSUMPTION, ["LLM10"]),
        }
        cat_key = ctx_finding.category.value if hasattr(ctx_finding.category, "value") else str(ctx_finding.category)
        attack_cat, owasp_ids = _CTX_CATEGORY.get(cat_key, (AttackCategory.PROMPT_INJECTION, ["LLM01"]))

        # Build evidence list with code context
        evidence_items: list[Evidence] = []

        # Primary evidence: surrounding code context
        code_ctx = getattr(ctx_finding, "code_context", None)
        if code_ctx:
            evidence_items.append(Evidence(
                type="code_context",
                content=code_ctx,
                source_file=str(ctx_finding.file_path) if ctx_finding.file_path else None,
                source_line=ctx_finding.line_number,
                metadata={"matched_text": ctx_finding.match_text or ""},
            ))

        # Secondary evidence: the specific pattern match
        evidence_items.append(Evidence(
            type="pattern_match",
            content=ctx_finding.line_content or ctx_finding.match_text or ctx_finding.description,
            source_file=str(ctx_finding.file_path) if ctx_finding.file_path else None,
            source_line=ctx_finding.line_number,
            metadata={
                "pattern_name": ctx_finding.pattern_name,
                "confidence_level": ConfidenceLevel.STATIC_MATCH.value,
            },
        ))

        cat_label = cat_key.replace("_", " ").title()

        return Finding(
            title=f"Potential {cat_label}: {ctx_finding.pattern_name}",
            description=(
                f"{ctx_finding.description}\n\n"
                f"Note: This is a static pattern match (unvalidated). "
                f"The pattern was detected in source code but has not been "
                f"confirmed via model interaction."
            ),
            severity=downgraded,
            confidence=0.4,
            category=attack_cat,
            component_type=ComponentType.CONTEXT,
            component_name=ctx_finding.pattern_name or "context",
            file_path=str(ctx_finding.file_path) if ctx_finding.file_path else None,
            line_number=ctx_finding.line_number,
            evidence=evidence_items,
            remediation=Remediation(
                summary=ctx_finding.remediation or "Review context configuration for security risks",
                steps=["Review and harden system prompts", "Validate context inputs"],
            ) if ctx_finding.remediation else None,
            owasp_ids=owasp_ids,
            tags=[
                cat_key,
                ConfidenceLevel.STATIC_MATCH.value,
            ],
            metadata={
                "confidence_level": ConfidenceLevel.STATIC_MATCH.value,
                "original_severity": ctx_finding.severity.value if hasattr(ctx_finding.severity, "value") else str(ctx_finding.severity),
            },
        )

    @staticmethod
    def _convert_infra_finding(infra_finding: Any) -> Finding:
        """Convert InfrastructureFinding to core Finding."""
        from mass.core.findings import Remediation
        from mass.core.types import AttackCategory, ComponentType

        return Finding(
            title=infra_finding.title,
            description=infra_finding.description,
            severity=infra_finding.severity,
            category=AttackCategory.SUPPLY_CHAIN,
            component_type=ComponentType.INFRASTRUCTURE,
            component_name=str(infra_finding.source) if hasattr(infra_finding, 'source') else "infrastructure",
            file_path=str(infra_finding.file_path) if hasattr(infra_finding, 'file_path') and infra_finding.file_path else None,
            line_number=infra_finding.line_number if hasattr(infra_finding, 'line_number') else None,
            remediation=Remediation(
                summary=infra_finding.remediation if hasattr(infra_finding, 'remediation') and infra_finding.remediation else "Review infrastructure configuration",
                steps=["Fix identified infrastructure misconfiguration"],
            ),
            cwe_ids=[infra_finding.cwe_id] if hasattr(infra_finding, 'cwe_id') and infra_finding.cwe_id else [],
            metadata={"confidence_level": "heuristic"},
        )

    @staticmethod
    def _convert_mcp_finding(mcp_finding: Any) -> Finding:
        """Convert MCPFinding to core Finding."""
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType

        return Finding(
            title=mcp_finding.title,
            description=mcp_finding.description,
            severity=mcp_finding.severity,
            category=AttackCategory.INSECURE_PLUGIN,
            component_type=ComponentType.MCP_SERVER,
            component_name=mcp_finding.server_name or "mcp-server",
            evidence=[Evidence(
                type="config",
                content=str(mcp_finding.evidence) if mcp_finding.evidence else mcp_finding.description,
            )] if mcp_finding.evidence else [],
            remediation=Remediation(
                summary=mcp_finding.remediation or "Review MCP server configuration",
                steps=["Audit MCP server permissions", "Apply principle of least privilege to tool access"],
            ) if mcp_finding.remediation else None,
            owasp_ids=["LLM05"],
            tags=[str(mcp_finding.category.value) if hasattr(mcp_finding.category, 'value') else str(mcp_finding.category)],
        )

    @staticmethod
    def _convert_static_mcp_finding(sf: Any) -> Finding:
        """Convert static MCP finding to core Finding."""
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType

        return Finding(
            title=sf.title,
            description=sf.description,
            severity=sf.severity,
            category=AttackCategory.INSECURE_PLUGIN,
            component_type=ComponentType.MCP_SERVER,
            component_name=str(sf.location.file_path.name) if sf.location else "mcp-server",
            evidence=[Evidence(
                type="code",
                content=sf.code_snippet or sf.description,
                metadata={"line": sf.location.line_number} if sf.location else {},
            )],
            remediation=Remediation(
                summary=sf.remediation or "Review MCP server code",
                steps=["Validate all tool inputs", "Use safe execution patterns"],
            ) if sf.remediation else None,
            owasp_ids=["LLM05"],
            tags=[str(sf.category.value) if hasattr(sf.category, 'value') else str(sf.category)],
            metadata={"file": str(sf.location.file_path), "line": sf.location.line_number} if sf.location else {},
        )

    def _analyze_typescript_mcp(
        self,
        root: "PathLib",
        file_index: list[str] | None,
    ) -> list[Finding]:
        """Analyze TypeScript MCP server code for tool definitions and security issues.

        Parses TypeScript/JavaScript MCP servers to extract tool definitions
        and check for common security issues.
        """
        import json
        import re
        from mass.core.findings import Evidence, Remediation
        from mass.core.types import AttackCategory, ComponentType, Severity

        findings: list[Finding] = []
        PathLib = type(root)

        # Find TypeScript MCP server files
        if file_index:
            ts_files = [
                f for f in file_index
                if (f.endswith('.ts') or f.endswith('.js')) and
                   ('mcp' in f.lower() or 'server' in f.lower())
            ]
        else:
            ts_files = [
                str(f.relative_to(root)) for f in root.glob("**/*.ts")
                if 'mcp' in f.name.lower() or 'server' in f.name.lower()
            ]
            ts_files.extend([
                str(f.relative_to(root)) for f in root.glob("**/*.js")
                if 'mcp' in f.name.lower() or 'server' in f.name.lower()
            ])

        # Dangerous patterns in MCP TypeScript code
        dangerous_patterns = [
            (r'eval\s*\(', Severity.CRITICAL, "eval() usage detected"),
            (r'Function\s*\(', Severity.CRITICAL, "Dynamic Function constructor"),
            (r'child_process', Severity.HIGH, "Child process usage"),
            (r'exec\s*\(', Severity.HIGH, "exec() call detected"),
            (r'execSync\s*\(', Severity.HIGH, "execSync() call detected"),
            (r'spawn\s*\(', Severity.MEDIUM, "spawn() call detected"),
            (r'fs\.write', Severity.MEDIUM, "Filesystem write detected"),
            (r'fs\.unlink', Severity.MEDIUM, "Filesystem delete detected"),
            (r'require\s*\(\s*[\'"]child_process[\'"]\s*\)', Severity.HIGH, "Child process import"),
        ]

        # Tool definition patterns to extract
        tool_pattern = re.compile(
            r'(server\.setRequestHandler|\.tool|addTool|registerTool)\s*\(\s*[\'"]?(\w+)',
            re.IGNORECASE
        )

        for rel_path in ts_files:
            abs_path = root / rel_path
            if not abs_path.exists():
                continue

            try:
                content = abs_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue

            # Check for dangerous patterns
            for pattern, severity, desc in dangerous_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    findings.append(Finding(
                        title=f"MCP Server: {desc}",
                        description=f"Potentially dangerous pattern found in MCP server code: {desc}",
                        severity=severity,
                        category=AttackCategory.INSECURE_PLUGIN,
                        component_type=ComponentType.MCP_SERVER,
                        component_name=abs_path.name,
                        evidence=[Evidence(
                            type="code",
                            content=line_content.strip()[:200],
                            metadata={"file": rel_path, "line": line_num},
                        )],
                        remediation=Remediation(
                            summary="Review and validate this code pattern",
                            steps=[
                                "Validate all inputs before processing",
                                "Avoid dynamic code execution",
                                "Use parameterized commands instead of shell execution",
                            ],
                        ),
                        owasp_ids=["LLM05"],
                        tags=["mcp", "code_execution"],
                        metadata={"file": rel_path, "line": line_num},
                    ))

            # Extract and log tool definitions
            tools_found = tool_pattern.findall(content)
            if tools_found:
                for method, tool_name in tools_found:
                    # Check if tool name suggests dangerous operations
                    dangerous_tool_names = ['exec', 'run', 'shell', 'command', 'delete', 'remove', 'write']
                    if any(d in tool_name.lower() for d in dangerous_tool_names):
                        findings.append(Finding(
                            title=f"MCP Tool with dangerous name: {tool_name}",
                            description=f"Tool '{tool_name}' has a name suggesting dangerous operations",
                            severity=Severity.MEDIUM,
                            category=AttackCategory.EXCESSIVE_AGENCY,
                            component_type=ComponentType.MCP_SERVER,
                            component_name=abs_path.name,
                            evidence=[Evidence(
                                type="tool_definition",
                                content=f"Tool: {tool_name}",
                                metadata={"file": rel_path},
                            )],
                            remediation=Remediation(
                                summary="Review tool permissions and input validation",
                                steps=[
                                    "Ensure tool validates all inputs",
                                    "Apply principle of least privilege",
                                    "Add rate limiting if appropriate",
                                ],
                            ),
                            owasp_ids=["LLM05", "LLM08"],
                            tags=["mcp", "tool_definition"],
                        ))

        return findings

    @staticmethod
    def _convert_attack_vector(vector: Any) -> Finding:
        """Convert AttackVector to core Finding.

        Attack vectors are topology-based predictions, not confirmed
        vulnerabilities.  They are downgraded one severity level and
        labelled with confidence_level=predicted so the dashboard can
        distinguish them from validated findings.
        """
        from mass.core.findings import Remediation
        from mass.core.types import AttackCategory, ComponentType, Severity

        # Map vector type to the closest OWASP LLM category
        _VECTOR_CATEGORY = {
            "user_input": AttackCategory.PROMPT_INJECTION,
            "rag_retrieval": AttackCategory.DATA_MODEL_POISONING,
            "tool_invocation": AttackCategory.INSECURE_PLUGIN,
            "agent_communication": AttackCategory.EXCESSIVE_AGENCY,
            "context_injection": AttackCategory.PROMPT_INJECTION,
            "external_service": AttackCategory.IMPROPER_OUTPUT,
            "file_upload": AttackCategory.SUPPLY_CHAIN,
            "memory_access": AttackCategory.DATA_LEAKAGE,
            "model_inference": AttackCategory.SENSITIVE_INFO,
            "api_endpoint": AttackCategory.IMPROPER_OUTPUT,
            "webhook": AttackCategory.IMPROPER_OUTPUT,
            "database_query": AttackCategory.DATA_LEAKAGE,
        }
        vtype = vector.vector_type.value if hasattr(vector.vector_type, "value") else str(vector.vector_type)
        category = _VECTOR_CATEGORY.get(vtype, AttackCategory.EXCESSIVE_AGENCY)

        # Downgrade severity by one level for unvalidated predictions
        _DOWN = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }
        severity = _DOWN.get(vector.severity, vector.severity)

        return Finding(
            title=f"Potential Risk: {vector.name}",
            description=(
                f"{vector.description} "
                f"This is a predicted risk based on deployment topology, "
                f"not a confirmed vulnerability."
            ),
            severity=severity,
            category=category,
            component_type=ComponentType.CODE,
            component_name=vector.entry_point,
            confidence=0.4,
            remediation=Remediation(
                summary="; ".join(vector.mitigations) if vector.mitigations else "Review attack vector and apply mitigations",
                steps=vector.mitigations or ["Analyze attack surface and reduce exposure"],
            ),
            mitre_ids=[str(vector.vector_type.value)] if hasattr(vector.vector_type, 'value') else [],
            tags=["predicted", "attack_surface"],
            metadata={
                "confidence_level": "predicted",
                "original_severity": vector.severity.value,
            },
        )

    @staticmethod
    def _convert_vuln_path(vpath: Any) -> Finding:
        """Convert VulnerabilityPath to core Finding.

        Vulnerability paths are topology-based predictions, downgraded
        and labelled accordingly.
        """
        from mass.core.findings import Remediation
        from mass.core.types import AttackCategory, ComponentType, Severity

        _DOWN = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }
        severity = _DOWN.get(vpath.severity, vpath.severity)
        likelihood = vpath.likelihood if hasattr(vpath, 'likelihood') else 0.3

        return Finding(
            title=f"Potential Path: {vpath.name}",
            description=(
                f"{vpath.description} "
                f"This is a predicted exploitation path based on component "
                f"topology, not a confirmed vulnerability."
            ),
            severity=severity,
            category=AttackCategory.EXCESSIVE_AGENCY,
            component_type=ComponentType.CODE,
            component_name=vpath.steps[0] if vpath.steps else "unknown",
            confidence=likelihood * 0.5,
            remediation=Remediation(
                summary=vpath.remediation or "Review and mitigate vulnerability path",
                steps=["Break the vulnerability chain at the weakest link"],
            ),
            tags=["predicted", "attack_surface"],
            metadata={
                "confidence_level": "predicted",
                "original_severity": vpath.severity.value,
            },
        )

    @staticmethod
    def _convert_workflow_finding(wf_finding: Any) -> Finding:
        """Convert WorkflowFinding to core Finding."""
        from mass.core.findings import Remediation
        from mass.core.types import AttackCategory, ComponentType

        return Finding(
            title=wf_finding.title,
            description=wf_finding.description,
            severity=wf_finding.severity,
            category=AttackCategory.EXCESSIVE_AGENCY,
            component_type=ComponentType.WORKFLOW,
            component_name=wf_finding.node_id or "workflow",
            remediation=Remediation(
                summary=wf_finding.remediation or "Review workflow for security risks",
                steps=["Audit agent workflow for unauthorized actions"],
            ) if wf_finding.remediation else None,
            tags=[str(wf_finding.category.value) if hasattr(wf_finding.category, 'value') else str(wf_finding.category)],
        )

    # --- File index utilities ---

    @staticmethod
    def _filter_files(
        file_index: list[str],
        extensions: set[str] | None = None,
        name_patterns: list[str] | None = None,
    ) -> list[str]:
        """Filter the shared file index by extensions or name patterns.

        Args:
            file_index: Pre-built list of relative file paths.
            extensions: Set of extensions to include (e.g. {".py", ".json"}).
            name_patterns: fnmatch patterns to match filenames against.

        Returns:
            Filtered list of relative paths.
        """
        import fnmatch

        matched = []
        for rel_path in file_index:
            filename = rel_path.rsplit("/", 1)[-1] if "/" in rel_path else rel_path
            lower_name = filename.lower()

            if extensions:
                # Check file extension
                dot_idx = lower_name.rfind(".")
                if dot_idx >= 0 and lower_name[dot_idx:] in extensions:
                    matched.append(rel_path)
                    continue

            if name_patterns:
                for pattern in name_patterns:
                    if fnmatch.fnmatch(lower_name, pattern.lower()):
                        matched.append(rel_path)
                        break
        return matched

    # --- Default handlers (synchronous, use shared file index) ---

    def _handle_deployment_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle deployment scanning job.

        DeploymentScanner.scan() returns a DeploymentManifest with discovered
        components, instructions, and configs. Uses its own lightweight traversal
        since it needs to build a full manifest. Runs first so downstream
        analyzers can use the manifest.
        """
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
            manifest = scanner.scan(path)

            summary = scanner.get_summary(manifest)
            result.output["summary"] = summary
            result.output["components_found"] = manifest.component_count
            result.output["instruction_count"] = manifest.instruction_count

            # Store manifest in context for downstream analyzers
            context["_manifest"] = manifest

            # Store environment and topology for downstream handlers
            context["_environment"] = manifest.metadata.get("environment", {})
            context["_topology"] = manifest.metadata.get("topology", {})

            result.output["environment"] = context["_environment"]

            result.items_processed = manifest.component_count
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_secret_detection(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle secret detection using shared file index.

        Filters for text files likely to contain secrets, then calls
        scan_file() on each instead of scan_directory() which would
        re-traverse the entire tree.
        """
        from pathlib import Path as PathLib
        from mass.analyzers.secrets.detector import SecretDetector

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            detector = SecretDetector()
            root = PathLib(path)
            env = context.get("_environment")

            # Filter to text files that could contain secrets
            secret_extensions = {
                ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
                ".rb", ".php", ".sh", ".bash", ".zsh", ".ps1",
                ".env", ".cfg", ".ini", ".conf",
                ".yaml", ".yml", ".json", ".toml", ".xml",
                ".tf", ".hcl",
                ".sql", ".graphql",
                ".md", ".txt", ".csv",
                ".properties", ".gradle",
            }

            if file_index:
                target_files = self._filter_files(file_index, extensions=secret_extensions)
            else:
                # Fallback: let detector do its own traversal
                detection_result = detector.scan_directory(root)
                result.output["files_scanned"] = detection_result.files_scanned
                result.output["secrets_found"] = len(detection_result.secrets)
                for sm in detection_result.secrets:
                    result.add_finding(self._convert_secret_match(sm, environment=env))
                result.mark_completed()
                return result

            total_secrets = 0
            for rel_path in target_files:
                try:
                    file_result = detector.scan_file(root / rel_path)
                    for sm in file_result.secrets:
                        result.add_finding(self._convert_secret_match(sm, environment=env))
                        total_secrets += 1
                except Exception:
                    pass  # Skip unreadable files

            result.items_processed = len(target_files)
            result.output["files_scanned"] = len(target_files)
            result.output["secrets_found"] = total_secrets
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_infrastructure_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle infrastructure scanning.

        InfrastructureScanner doesn't have per-file methods, so we pass
        the deployment path. It scans for Docker, K8s, and Terraform files.
        For large targets, the file index already excluded irrelevant dirs.
        """
        from mass.analyzers.infrastructure.scanner import InfrastructureScanner

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            # Check if there are any infrastructure files before running
            if file_index:
                infra_files = self._filter_files(
                    file_index,
                    extensions={".tf", ".hcl"},
                    name_patterns=["Dockerfile*", "docker-compose*", "*.yaml", "*.yml"],
                )
                if not infra_files:
                    result.mark_completed()
                    result.output["message"] = "No infrastructure files found"
                    return result

            scanner = InfrastructureScanner()
            scan_result = scanner.scan(path)

            result.output["files_scanned"] = scan_result.files_scanned
            result.output["resources_scanned"] = scan_result.resources_scanned
            result.items_processed = scan_result.files_scanned

            for infra_finding in scan_result.findings:
                finding = self._convert_infra_finding(infra_finding)
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_model_file_scan(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle model file scanning using shared file index.

        Filters for model file extensions, then calls scan_file() on each.
        Skips files > 100MB for metadata-only analysis (future enhancement).
        """
        from pathlib import Path as PathLib
        from mass.analyzers.model_file.scanner import ModelFileScanner

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            scanner = ModelFileScanner()
            root = PathLib(path)

            model_extensions = {
                ".gguf", ".pt", ".pth", ".bin", ".safetensors",
                ".onnx", ".pb", ".h5", ".keras", ".tflite",
                ".mlmodel", ".pmml", ".pkl", ".joblib",
            }

            if file_index:
                target_files = self._filter_files(file_index, extensions=model_extensions)
            else:
                file_results = scanner.scan_directory(root)
                result.output["model_files_scanned"] = len(file_results)
                for fr in file_results:
                    for mf in fr.findings:
                        result.add_finding(self._convert_model_file_finding(mf, str(fr.file_path)))
                result.mark_completed()
                return result

            result.output["model_files_scanned"] = len(target_files)

            for rel_path in target_files:
                abs_path = root / rel_path
                # Skip very large model files (>500MB) - metadata-only mode TODO
                try:
                    file_size = abs_path.stat().st_size
                    if file_size > 500 * 1024 * 1024:
                        result.output.setdefault("skipped_large", []).append(
                            f"{rel_path} ({file_size // (1024*1024)}MB)"
                        )
                        continue
                except OSError:
                    continue

                try:
                    file_result = scanner.scan_file(abs_path)
                    for mf_finding in file_result.findings:
                        finding = self._convert_model_file_finding(
                            mf_finding, str(abs_path)
                        )
                        result.add_finding(finding)
                except Exception:
                    result.output.setdefault("errors", []).append(
                        f"Failed to scan: {rel_path}"
                    )

            result.items_processed = len(target_files)
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    # Binary/model extensions that should never be context-analyzed.
    # These are handled by model_file_scan or are not text files.
    _BINARY_EXTENSIONS = {
        ".gguf", ".pt", ".pth", ".bin", ".safetensors",
        ".onnx", ".pb", ".h5", ".keras", ".tflite",
        ".mlmodel", ".pmml", ".pkl", ".joblib",
        ".pyc", ".pyo", ".so", ".dll", ".dylib",
        ".exe", ".o", ".a", ".lib",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    }

    # Max file size for context analysis (512 KB).  Legitimate prompt
    # templates, system instructions, and config files are small text;
    # anything larger is almost certainly not an AI context file.
    _CONTEXT_MAX_FILE_SIZE = 512 * 1024

    @staticmethod
    def _is_binary_file(file_path: str, read_size: int = 8192) -> bool:
        """Detect binary files via magic number registry and null-byte heuristic.

        Uses the shared magic number library at
        ``mass.analyzers.model_file.magic`` which covers model formats
        (GGUF, pickle, safetensors, etc.) and common binary formats.

        Args:
            file_path: Absolute path to the file.
            read_size: Number of bytes to sample (default 8 KB).

        Returns:
            True if the file is detected as binary.
        """
        from mass.analyzers.model_file.magic import is_binary_file
        return is_binary_file(file_path, read_size=read_size)

    def _handle_context_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle context analysis using shared file index.

        Filters for text files likely to contain prompts, context, or
        system instructions, then calls analyze_file() on each.
        Binary files and files over 512 KB are skipped.
        """
        import os
        from pathlib import Path as PathLib
        from mass.analyzers.context.analyzer import ContextAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            analyzer = ContextAnalyzer()
            root = PathLib(path)

            if file_index:
                # Context files: prompts, configs, instructions, system messages
                target_files = self._filter_files(
                    file_index,
                    name_patterns=[
                        "*prompt*", "*context*", "*system*", "*instruct*",
                        "*persona*", "*template*", "*guardrail*",
                        "*.yaml", "*.yml", "*.json", "*.toml",
                        "*.txt", "*.md",
                    ],
                )
                # Also include Python files that might contain inline prompts
                py_files = self._filter_files(file_index, extensions={".py"})
                target_files = list(set(target_files + py_files))

                # Exclude binary/model files that other scanners handle
                target_files = [
                    f for f in target_files
                    if os.path.splitext(f)[1].lower() not in self._BINARY_EXTENSIONS
                ]
            else:
                analysis_results = analyzer.analyze_directory(root)
                result.output["files_analyzed"] = len(analysis_results)
                for ar in analysis_results:
                    for cf in ar.findings:
                        result.add_finding(self._convert_context_finding(cf))
                result.mark_completed()
                return result

            result.output["files_analyzed"] = len(target_files)
            files_with_findings = 0
            skipped_large = 0

            skipped_binary = 0

            for rel_path in target_files:
                try:
                    abs_path = root / rel_path
                    abs_str = str(abs_path)
                    # Skip files over size limit
                    try:
                        if abs_path.stat().st_size > self._CONTEXT_MAX_FILE_SIZE:
                            skipped_large += 1
                            continue
                    except OSError:
                        continue

                    # Skip binary files (magic number + null-byte check)
                    if self._is_binary_file(abs_str):
                        skipped_binary += 1
                        continue

                    analysis_result = analyzer.analyze_file(abs_path)
                    if analysis_result.findings:
                        files_with_findings += 1
                    for ctx_finding in analysis_result.findings:
                        finding = self._convert_context_finding(ctx_finding)
                        result.add_finding(finding)
                except Exception:
                    pass  # Skip unanalyzable files

            result.items_processed = len(target_files) - skipped_large - skipped_binary
            result.output["files_with_findings"] = files_with_findings
            if skipped_large:
                result.output["skipped_oversized"] = skipped_large
            if skipped_binary:
                result.output["skipped_binary"] = skipped_binary
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_mcp_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle MCP analysis using shared file index.

        Filters for MCP config files from the index instead of globbing.
        """
        from pathlib import Path as PathLib
        from mass.analyzers.mcp.analyzer import MCPAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            analyzer = MCPAnalyzer()
            root = PathLib(path)

            # Find MCP config files
            if file_index:
                mcp_config_files = self._filter_files(
                    file_index,
                    name_patterns=["*mcp*.json", "*mcp*.yaml", "*mcp*.yml",
                                   "*mcp_config*", "*mcp_servers*",
                                   "claude_desktop_config.json"],
                )
            else:
                deploy_path = PathLib(path)
                mcp_config_files_abs = []
                for pattern in ["**/mcp*.json", "**/mcp*.yaml", "**/mcp*.yml",
                                "**/claude_desktop_config.json"]:
                    mcp_config_files_abs.extend(deploy_path.glob(pattern))
                mcp_config_files = [str(f) for f in mcp_config_files_abs]

            result.output["config_files_found"] = len(mcp_config_files)

            # Analyze MCP config files
            for rel_path in mcp_config_files:
                abs_path = root / rel_path if file_index else PathLib(rel_path)
                try:
                    analysis_results = analyzer.analyze_config_file(abs_path)
                    for analysis_result in analysis_results:
                        for mcp_finding in analysis_result.findings:
                            finding = self._convert_mcp_finding(mcp_finding)
                            result.add_finding(finding)
                except Exception:
                    result.output.setdefault("errors", []).append(
                        f"Failed to analyze config: {rel_path}"
                    )

            # Also analyze MCP source files (Python)
            from mass.analyzers.mcp.static import MCPStaticAnalyzer
            static_analyzer = MCPStaticAnalyzer()

            if file_index:
                mcp_source_files = self._filter_files(
                    file_index,
                    name_patterns=["*mcp*server*.py", "*server*.py"],
                    extensions=[".py"],
                )
            else:
                deploy_path = PathLib(path)
                mcp_source_files = [
                    str(f) for f in deploy_path.glob("**/*server*.py")
                ]

            result.output["source_files_found"] = len(mcp_source_files)

            for rel_path in mcp_source_files:
                abs_path = root / rel_path if file_index else PathLib(rel_path)
                try:
                    static_findings = static_analyzer.analyze_file(abs_path)
                    for sf in static_findings:
                        finding = self._convert_static_mcp_finding(sf)
                        result.add_finding(finding)
                except Exception:
                    result.output.setdefault("errors", []).append(
                        f"Failed to analyze source: {rel_path}"
                    )

            # Analyze TypeScript MCP source files for tool definitions
            ts_findings = self._analyze_typescript_mcp(root, file_index)
            for finding in ts_findings:
                result.add_finding(finding)
            result.output["ts_tools_analyzed"] = len(ts_findings)

            result.items_processed = len(mcp_config_files) + len(mcp_source_files)
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_attack_surface(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle attack surface analysis.

        Uses deployment manifest (no file traversal needed).
        """
        from mass.analyzers.attack_surface.analyzer import AttackSurfaceAnalyzer
        from mass.core.types import ComponentType

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            manifest = context.get("_manifest")
            components: dict[str, ComponentType] = {}

            if manifest and hasattr(manifest, 'components'):
                for comp in manifest.components:
                    comp_name = comp.name if hasattr(comp, 'name') else str(comp)
                    comp_type_str = comp.component_type if hasattr(comp, 'component_type') else "unknown"
                    try:
                        components[comp_name] = ComponentType(comp_type_str)
                    except (ValueError, KeyError):
                        components[comp_name] = ComponentType.CODE

            if not components:
                result.mark_completed()
                result.output["message"] = "No components discovered for attack surface analysis"
                return result

            analyzer = AttackSurfaceAnalyzer()
            analysis_result = analyzer.analyze(components)

            result.output["attack_vectors"] = len(analysis_result.attack_vectors)
            result.output["vulnerability_paths"] = len(analysis_result.vulnerability_paths)

            for vector in analysis_result.attack_vectors:
                finding = self._convert_attack_vector(vector)
                result.add_finding(finding)

            for vpath in analysis_result.vulnerability_paths:
                finding = self._convert_vuln_path(vpath)
                result.add_finding(finding)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_workflow_analysis(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle workflow analysis using shared file index.

        Filters for agent/workflow Python files from the index.
        """
        from pathlib import Path as PathLib
        from mass.analyzers.workflow.analyzer import WorkflowAnalyzer

        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            path = context.get("deployment_path")
            file_index = context.get("file_index")
            if not path:
                result.mark_completed()
                return result

            analyzer = WorkflowAnalyzer()
            root = PathLib(path)

            if file_index:
                workflow_files = self._filter_files(
                    file_index,
                    name_patterns=[
                        "*agent*.py", "*workflow*.py", "*chain*.py",
                        "*graph*.py", "*pipeline*.py", "*planner*.py",
                    ],
                )
            else:
                deploy_path = PathLib(path)
                wf_abs = []
                for pattern in ["**/*agent*.py", "**/*workflow*.py", "**/*chain*.py"]:
                    wf_abs.extend(deploy_path.glob(pattern))
                workflow_files = [str(f) for f in wf_abs]

            result.output["workflow_files_found"] = len(workflow_files)

            for rel_path in workflow_files:
                abs_path = root / rel_path if file_index else PathLib(rel_path)
                try:
                    analysis_result = analyzer.analyze_file(abs_path)
                    for wf_finding in analysis_result.findings:
                        finding = self._convert_workflow_finding(wf_finding)
                        result.add_finding(finding)
                except Exception:
                    result.output.setdefault("errors", []).append(
                        f"Failed to analyze: {rel_path}"
                    )

            result.items_processed = len(workflow_files)
            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _handle_model_interrogation(
        self, job: PlannedJob, context: dict[str, Any]
    ) -> JobResult:
        """Handle model interrogation job.

        Runs probes against a live model endpoint to discover vulnerabilities.
        Static analysis of model files is handled by model_file_scan.
        """
        result = JobResult(job_id=job.id, job_type=job.job_type)
        result.mark_started()

        try:
            endpoint = context.get("model_endpoint")
            provider = context.get("model_provider", "openai")
            model_name = context.get("model_name")
            api_key = context.get("model_api_key")
            system_prompt = context.get("system_prompt")
            target_type = context.get("target_type", "deployment")

            # For agent_endpoint, fall back to agent_url if no model_endpoint
            if target_type == "agent_endpoint" and not endpoint:
                endpoint = context.get("agent_url")

            if not endpoint:
                result.mark_completed()
                result.output["message"] = (
                    "No model endpoint configured - "
                    "dynamic analysis requires a running model"
                )
                return result

            # Create runner for the model/agent
            from mass.runners.factory import create_runner

            runner_kwargs: dict[str, Any] = {}
            if api_key:
                runner_kwargs["api_key"] = api_key

            # Route endpoint parameter based on provider type
            provider_lower = provider.lower()
            if provider_lower in ("azure_openai", "azure"):
                runner_kwargs["azure_endpoint"] = endpoint
            elif provider_lower in ("openai", "ollama", "custom", "grok", "xai"):
                runner_kwargs["base_url"] = endpoint
            # bedrock, gemini/google don't use endpoint URLs directly

            runner = create_runner(provider, model=model_name, **runner_kwargs)
            if not runner:
                result.mark_failed(
                    f"Could not create runner for provider '{provider}'"
                )
                return result

            # Configure probe execution
            from mass.orchestration.probe_executor import (
                ProbeExecutor,
                ProbeExecutorConfig,
            )

            # Get probe config from job config
            job_cfg = job.config or {}
            probe_categories = job_cfg.get("probe_categories")

            config = ProbeExecutorConfig(
                categories=probe_categories,
                system_prompt=system_prompt,
                model_name=model_name or "unknown",
                prompt_timeout=float(job.timeout_seconds or 30),
                max_probes=int(job_cfg.get("max_probes", 0)),
                max_prompts_per_probe=int(job_cfg.get("max_prompts_per_probe", 0)),
                max_concurrent_probes=int(job_cfg.get("max_concurrent_probes", 3)),
                max_concurrent_prompts=int(job_cfg.get("max_concurrent_prompts", 2)),
            )

            # Pass remediation cache for enriched finding guidance
            from mass.orchestration.remediation_resolver import REMEDIATION_CACHE_KEY
            remediation_cache = context.get(REMEDIATION_CACHE_KEY)

            executor = ProbeExecutor(runner, config, remediation_cache=remediation_cache)
            probe_result = executor.execute()

            # Transfer findings to job result
            for finding in probe_result.findings:
                result.add_finding(finding)

            result.items_processed = probe_result.prompts_sent
            result.items_total = probe_result.prompts_sent
            result.output = {
                "probes_run": probe_result.probes_run,
                "prompts_sent": probe_result.prompts_sent,
                "prompts_failed": probe_result.prompts_failed,
                "vulnerable": probe_result.vulnerable_count,
                "safe": probe_result.safe_count,
                "uncertain": probe_result.uncertain_count,
                "duration_seconds": probe_result.duration_seconds,
                "errors": probe_result.errors[:10],
            }

            # Include agent-to-agent context in output for richer reporting
            if target_type == "agent_endpoint":
                result.output["target_type"] = "agent_endpoint"
                result.output["agent_protocol"] = context.get("agent_protocol", "rest")
                if context.get("upstream_agents"):
                    result.output["upstream_agents"] = context["upstream_agents"]
                if context.get("downstream_agents"):
                    result.output["downstream_agents"] = context["downstream_agents"]

            # Run multi-turn AI interrogation if attacker model is configured
            attacker_provider = context.get("attacker_provider") or job_cfg.get("attacker_provider")
            attacker_model = context.get("attacker_model") or job_cfg.get("attacker_model")
            if attacker_provider and attacker_model:
                try:
                    interrogation_findings = self._run_interrogation(
                        context, job_cfg, attacker_provider, attacker_model,
                    )
                    for finding in interrogation_findings:
                        result.add_finding(finding)
                    result.output["interrogation_findings"] = len(interrogation_findings)
                except Exception as e:
                    logger.warning("Interrogation failed: %s", e, exc_info=True)
                    result.output["interrogation_error"] = str(e)

            result.mark_completed()

        except Exception as e:
            result.mark_failed(str(e))

        return result

    def _run_interrogation(
        self,
        context: dict[str, Any],
        job_cfg: dict[str, Any],
        attacker_provider: str,
        attacker_model: str,
    ) -> list:
        """Run multi-turn AI interrogation using the interrogator module."""
        from mass.interrogator.orchestrator import (
            InterrogationConfig,
            InterrogationOrchestrator,
        )

        config = InterrogationConfig(
            target_provider=context.get("model_provider", "openai"),
            target_model=context.get("model_name", ""),
            target_endpoint=context.get("model_endpoint"),
            target_api_key=context.get("model_api_key"),
            target_system_prompt=context.get("system_prompt"),
            attacker_provider=attacker_provider,
            attacker_model=attacker_model,
            attacker_endpoint=context.get("attacker_endpoint") or job_cfg.get("attacker_endpoint"),
            attacker_api_key=context.get("attacker_api_key") or job_cfg.get("attacker_api_key"),
            categories=job_cfg.get("interrogation_categories"),
            max_turns=int(job_cfg.get("interrogation_max_turns", 8)),
            max_strategies_per_agent=int(job_cfg.get("interrogation_max_strategies", 2)),
        )

        orchestrator = InterrogationOrchestrator(config)
        result = orchestrator.execute()

        logger.info(
            "Interrogation: %d agents, %d successful attacks, %d findings",
            result.agents_run, result.successful_attacks, len(result.findings),
        )

        return result.findings
