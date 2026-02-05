"""Direct analysis endpoints.

Allows one-off analysis of specific component types without creating
a full deployment and scan.
"""

import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel, ConfigDict, Field

from mass.api.dependencies import CurrentTenantDep
from mass.core.types import AttackCategory, Severity

router = APIRouter()


class AnalysisRequest(BaseModel):
    """Base analysis request."""

    model_config = ConfigDict(extra="forbid")

    profile: str = Field(default="standard", description="Analysis profile")
    categories: list[str] | None = Field(default=None, description="Categories to test")
    timeout_seconds: int = Field(default=300, description="Maximum analysis time")


class ModelAnalysisRequest(AnalysisRequest):
    """Request for model analysis."""

    model_provider: str = Field(..., description="Model provider: openai, anthropic, local, etc.")
    model_name: str = Field(..., description="Model name or path")
    model_endpoint: str | None = Field(default=None, description="Custom endpoint URL")
    system_prompt: str | None = Field(default=None, description="System prompt to test with")
    api_key: str | None = Field(default=None, description="API key for the model (encrypted)")
    max_probes: int = Field(default=0, description="Maximum probes to run (0 = all)")
    max_prompts_per_probe: int = Field(default=0, description="Maximum prompts per probe (0 = all)")


class ContextAnalysisRequest(AnalysisRequest):
    """Request for context/prompt analysis."""

    content: str = Field(..., description="Context content to analyze")
    context_type: str = Field(default="system_prompt", description="Type: system_prompt, persona, skill")


class MCPAnalysisRequest(AnalysisRequest):
    """Request for MCP server analysis."""

    server_name: str = Field(default="unknown", description="MCP server name")
    server_url: str | None = Field(default=None, description="MCP server URL")
    command: str | None = Field(default=None, description="Server command (for stdio)")
    args: list[str] | None = Field(default=None, description="Command arguments")
    transport: str = Field(default="sse", description="Transport type: sse, stdio, http")
    auth_token: str | None = Field(default=None, description="Authentication token")
    tools: list[dict[str, Any]] | None = Field(default=None, description="Tool definitions")
    env: dict[str, str] | None = Field(default=None, description="Environment variables")


class CodeAnalysisRequest(AnalysisRequest):
    """Request for code analysis."""

    content: str | None = Field(default=None, description="Code content to analyze")
    file_path: str | None = Field(default=None, description="Path to analyze (for repository scans)")
    language: str | None = Field(default=None, description="Programming language hint")


class WorkflowAnalysisRequest(AnalysisRequest):
    """Request for workflow analysis."""

    content: str | None = Field(default=None, description="Workflow definition content")
    framework: str | None = Field(default=None, description="Framework: langchain, langgraph, crewai, autogen")
    entry_point: str | None = Field(default=None, description="Entry point file or function")


class EvidenceItem(BaseModel):
    """A single piece of evidence for audit/oversight."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., description="Evidence type: prompt, response, detection, code, config")
    content: str = Field(..., description="Evidence content (prompt text, response text, etc.)")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class AnalysisFinding(BaseModel):
    """A finding from direct analysis."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Finding description")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Attack category")
    confidence: float = Field(default=1.0, description="Confidence score")
    file_path: str | None = Field(default=None, description="File path")
    line_number: int | None = Field(default=None, description="Line number")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="Evidence trail for oversight")
    remediation: str | None = Field(default=None, description="Remediation guidance")
    remediation_steps: list[str] = Field(default_factory=list, description="Step-by-step remediation")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    cwe_ids: list[str] = Field(default_factory=list, description="Related CWE IDs")
    owasp_ids: list[str] = Field(default_factory=list, description="Related OWASP IDs")


class AnalysisResponse(BaseModel):
    """Response from direct analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(..., description="Analysis ID")
    status: str = Field(..., description="Analysis status")
    component_type: str = Field(..., description="Component type analyzed")
    findings: list[AnalysisFinding] = Field(..., description="Discovered findings")
    summary: dict[str, int] = Field(..., description="Findings summary by severity")
    duration_seconds: float = Field(..., description="Analysis duration")


def _severity_summary(findings: list[AnalysisFinding]) -> dict[str, int]:
    """Build severity count summary from findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts


@router.post(
    "/model",
    response_model=AnalysisResponse,
    summary="Analyze model",
    description="Run dynamic security probes against an LLM model endpoint.",
)
async def analyze_model(
    request: ModelAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze an LLM model for security vulnerabilities.

    Sends adversarial probes to the model and analyzes responses
    using detectors to identify jailbreak, injection, and leakage vulnerabilities.
    """
    start = time.time()

    if not request.model_endpoint and not request.model_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either model_endpoint or model_provider must be provided",
        )

    from mass.runners.factory import create_runner
    from mass.orchestration.probe_executor import ProbeExecutor, ProbeExecutorConfig

    # Create runner
    runner_kwargs: dict[str, Any] = {}
    if request.api_key:
        runner_kwargs["api_key"] = request.api_key
    if request.model_endpoint:
        runner_kwargs["base_url"] = request.model_endpoint

    provider = request.model_provider or "openai"
    runner = create_runner(provider, model=request.model_name, **runner_kwargs)
    if not runner:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not create runner for provider '{provider}'",
        )

    # Parse categories from request
    categories = request.categories if request.categories else None

    config = ProbeExecutorConfig(
        categories=categories,
        system_prompt=request.system_prompt,
        model_name=request.model_name or provider,
        prompt_timeout=float(request.timeout_seconds),
        max_probes=request.max_probes,
        max_prompts_per_probe=request.max_prompts_per_probe,
    )

    executor = ProbeExecutor(runner, config)
    probe_result = executor.execute()

    # Convert to response with full evidence trail
    findings = []
    for f in probe_result.findings:
        # Build evidence items from the Finding's Evidence objects
        evidence_items = []
        for ev in (f.evidence or []):
            evidence_items.append(EvidenceItem(
                type=ev.type,
                content=ev.content,
                metadata=ev.metadata,
            ))

        findings.append(AnalysisFinding(
            title=f.title,
            description=f.description,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            category=f.category.value if hasattr(f.category, "value") else str(f.category),
            confidence=f.confidence,
            evidence=evidence_items,
            remediation=f.remediation.summary if f.remediation else None,
            remediation_steps=f.remediation.steps if f.remediation else [],
            references=f.remediation.references if f.remediation else [],
            cwe_ids=f.cwe_ids or [],
            owasp_ids=f.owasp_ids or [],
        ))

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="model",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )


@router.post(
    "/context",
    response_model=AnalysisResponse,
    summary="Analyze context",
    description="Analyze context/prompt content for vulnerabilities.",
)
async def analyze_context(
    request: ContextAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze context content (system prompts, personas, skills)."""
    start = time.time()

    from mass.analyzers.context.analyzer import ContextAnalyzer

    analyzer = ContextAnalyzer()
    result = analyzer.analyze_content(request.content)

    findings = []
    for f in result.findings:
        # Build evidence from the matched content
        evidence_items = []
        if hasattr(f, "line_content") and f.line_content:
            evidence_items.append(EvidenceItem(
                type="matched_content",
                content=f.line_content,
                metadata={
                    "line_number": f.line_number,
                    "match_text": f.match_text if hasattr(f, "match_text") else None,
                    "pattern_name": f.pattern_name if hasattr(f, "pattern_name") else None,
                },
            ))
        if hasattr(f, "match_text") and f.match_text and f.match_text != (f.line_content if hasattr(f, "line_content") else None):
            evidence_items.append(EvidenceItem(
                type="pattern_match",
                content=f.match_text,
                metadata={"pattern_name": f.pattern_name if hasattr(f, "pattern_name") else None},
            ))

        findings.append(AnalysisFinding(
            title=f.title if hasattr(f, "title") else str(f.pattern_name if hasattr(f, "pattern_name") else "Finding"),
            description=f.description if hasattr(f, "description") else "",
            severity=str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
            category=str(f.category.value) if hasattr(f.category, "value") else str(f.category) if hasattr(f, "category") else "unknown",
            confidence=f.confidence if hasattr(f, "confidence") else 1.0,
            file_path=str(f.file_path) if hasattr(f, "file_path") and f.file_path else None,
            line_number=f.line_number if hasattr(f, "line_number") else None,
            evidence=evidence_items,
            remediation=f.remediation if hasattr(f, "remediation") else None,
        ))

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="context",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )


@router.post(
    "/mcp",
    response_model=AnalysisResponse,
    summary="Analyze MCP server",
    description="Analyze an MCP server configuration for vulnerabilities.",
)
async def analyze_mcp(
    request: MCPAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze an MCP server for security vulnerabilities (static config analysis)."""
    start = time.time()

    from mass.analyzers.mcp.analyzer import MCPAnalyzer, MCPServerInfo

    server_info = MCPServerInfo(
        name=request.server_name,
        command=request.command,
        url=request.server_url,
        server_type=request.transport,
        tools=request.tools or [],
        resources=[],
        prompts=[],
        config={
            "auth_token": request.auth_token,
            "args": request.args,
            **(request.env or {}),
        },
    )

    analyzer = MCPAnalyzer()
    result = analyzer.analyze_server(server_info)

    findings = []
    for f in result.findings:
        # Build evidence from MCP config that triggered the finding
        evidence_items = []
        if hasattr(f, "evidence") and f.evidence:
            for ev_key, ev_val in (f.evidence if isinstance(f.evidence, dict) else {}).items():
                evidence_items.append(EvidenceItem(
                    type="config",
                    content=str(ev_val),
                    metadata={"field": ev_key},
                ))
        # Include the MCP server config as context evidence
        if not evidence_items:
            evidence_items.append(EvidenceItem(
                type="config",
                content=f"Server: {request.server_name}, Transport: {request.transport}, Command: {request.command}",
                metadata={
                    "server_name": request.server_name,
                    "transport": request.transport,
                    "tools_count": len(request.tools or []),
                },
            ))

        findings.append(AnalysisFinding(
            title=f.title if hasattr(f, "title") else str(f),
            description=f.description if hasattr(f, "description") else "",
            severity=str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
            category=str(f.category.value) if hasattr(f.category, "value") else str(f.category) if hasattr(f, "category") else "unknown",
            confidence=f.confidence if hasattr(f, "confidence") else 1.0,
            evidence=evidence_items,
            remediation=f.remediation if hasattr(f, "remediation") else None,
        ))

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="mcp_server",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )


@router.post(
    "/code",
    response_model=AnalysisResponse,
    summary="Analyze code",
    description="Analyze application code for AI security issues.",
)
async def analyze_code(
    request: CodeAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze application code for secrets and security issues."""
    if not request.content and not request.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either content or file_path must be provided",
        )

    start = time.time()

    from mass.analyzers.secrets.detector import SecretDetector

    detector = SecretDetector()
    findings = []

    def _secret_to_finding(match: Any, file_path_default: str | None = None) -> AnalysisFinding:
        """Convert a secret match to a finding with evidence."""
        evidence_items = []
        # Show the line where the secret was found (with the actual value masked)
        if hasattr(match, "line_content") and match.line_content:
            evidence_items.append(EvidenceItem(
                type="code",
                content=match.line_content,
                metadata={
                    "line_number": match.line_number,
                    "pattern_name": match.pattern_name,
                },
            ))
        # Show the masked secret value
        if hasattr(match, "masked_value") and match.masked_value:
            evidence_items.append(EvidenceItem(
                type="secret_match",
                content=f"Detected: {match.masked_value}",
                metadata={
                    "category": str(match.category.value) if hasattr(match.category, "value") else str(match.category),
                    "entropy": match.entropy if hasattr(match, "entropy") else None,
                },
            ))

        return AnalysisFinding(
            title=f"Secret Detected: {match.pattern_name}",
            description=match.description if hasattr(match, "description") else f"Potential secret: {match.pattern_name}",
            severity=str(match.severity.value) if hasattr(match.severity, "value") else str(match.severity),
            category="secrets_exposure",
            confidence=match.confidence if hasattr(match, "confidence") else 1.0,
            file_path=str(match.file_path) if hasattr(match, "file_path") and match.file_path else file_path_default,
            line_number=match.line_number if hasattr(match, "line_number") else None,
            evidence=evidence_items,
            remediation="Remove hardcoded secret and use environment variables or a secrets manager.",
        )

    if request.content:
        result = detector.scan_content(request.content)
        for match in result.secrets:
            findings.append(_secret_to_finding(match))
    elif request.file_path:
        file_p = Path(request.file_path)
        if not file_p.exists():
            raise HTTPException(status_code=400, detail=f"File not found: {request.file_path}")
        result = detector.scan_file(file_p)
        for match in result.secrets:
            findings.append(_secret_to_finding(match, request.file_path))

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="code",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )


@router.post(
    "/workflow",
    response_model=AnalysisResponse,
    summary="Analyze workflow",
    description="Analyze an agentic workflow for vulnerabilities.",
)
async def analyze_workflow(
    request: WorkflowAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze an agentic workflow for security vulnerabilities."""
    start = time.time()

    findings = []

    if request.content:
        # Write content to temp file for analyzer
        import tempfile
        import os
        suffix = ".py"
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tmp:
            tmp.write(request.content)
            tmp_path = tmp.name

        try:
            from mass.analyzers.workflow.analyzer import WorkflowAnalyzer
            analyzer = WorkflowAnalyzer()
            result = analyzer.analyze_file(Path(tmp_path))

            for f in result.findings:
                evidence_items = []
                if hasattr(f, "evidence") and f.evidence:
                    for ev in (f.evidence if isinstance(f.evidence, list) else [f.evidence]):
                        evidence_items.append(EvidenceItem(
                            type="workflow_analysis",
                            content=str(ev),
                            metadata={},
                        ))
                elif hasattr(f, "file_path") and f.file_path:
                    evidence_items.append(EvidenceItem(
                        type="code",
                        content=f"File: {f.file_path}, Line: {f.line_number if hasattr(f, 'line_number') else 'N/A'}",
                        metadata={"framework": request.framework},
                    ))

                findings.append(AnalysisFinding(
                    title=f.title if hasattr(f, "title") else str(f),
                    description=f.description if hasattr(f, "description") else "",
                    severity=str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
                    category=str(f.category.value) if hasattr(f.category, "value") else str(f.category) if hasattr(f, "category") else "excessive_agency",
                    confidence=f.confidence if hasattr(f, "confidence") else 1.0,
                    evidence=evidence_items,
                    remediation=f.remediation if hasattr(f, "remediation") else None,
                ))
        finally:
            os.unlink(tmp_path)

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="workflow",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )


@router.post(
    "/file",
    response_model=AnalysisResponse,
    summary="Analyze model file",
    description="Analyze a model file for malicious content.",
)
async def analyze_model_file(
    file: UploadFile = File(..., description="Model file to analyze"),
    profile: str = Form(default="standard"),
    tenant: CurrentTenantDep = None,
) -> AnalysisResponse:
    """Analyze a model file for security issues."""
    import tempfile
    import os

    start = time.time()

    # Check file size (limit to 10GB)
    max_size = 10 * 1024 * 1024 * 1024
    content = await file.read()

    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large. Maximum size is 10GB.",
        )

    # Write to temp file for scanner
    suffix = Path(file.filename).suffix if file.filename else ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    findings = []
    try:
        from mass.analyzers.model_file.scanner import ModelFileScanner
        scanner = ModelFileScanner()
        result = scanner.scan_file(Path(tmp_path))

        for f in result.findings:
            evidence_items = []
            if hasattr(f, "evidence") and f.evidence:
                for ev in (f.evidence if isinstance(f.evidence, list) else [f.evidence]):
                    evidence_items.append(EvidenceItem(
                        type="file_analysis",
                        content=str(ev),
                        metadata={"filename": file.filename},
                    ))
            else:
                evidence_items.append(EvidenceItem(
                    type="file_analysis",
                    content=f"Scanned file: {file.filename} ({len(content)} bytes)",
                    metadata={"file_size": len(content), "suffix": suffix},
                ))

            findings.append(AnalysisFinding(
                title=f.title if hasattr(f, "title") else str(f),
                description=f.description if hasattr(f, "description") else "",
                severity=str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
                category=str(f.category.value) if hasattr(f.category, "value") else str(f.category) if hasattr(f, "category") else "supply_chain",
                confidence=f.confidence if hasattr(f, "confidence") else 1.0,
                file_path=file.filename,
                evidence=evidence_items,
                remediation=f.remediation if hasattr(f, "remediation") else None,
            ))
    finally:
        os.unlink(tmp_path)

    duration = time.time() - start
    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="model_file",
        findings=findings,
        summary=_severity_summary(findings),
        duration_seconds=round(duration, 3),
    )
