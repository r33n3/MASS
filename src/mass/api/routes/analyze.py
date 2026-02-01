"""Direct analysis endpoints.

Allows one-off analysis of specific component types without creating
a full deployment and scan.
"""

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


class ContextAnalysisRequest(AnalysisRequest):
    """Request for context/prompt analysis."""

    content: str = Field(..., description="Context content to analyze")
    context_type: str = Field(default="system_prompt", description="Type: system_prompt, persona, skill")


class MCPAnalysisRequest(AnalysisRequest):
    """Request for MCP server analysis."""

    server_url: str = Field(..., description="MCP server URL")
    transport: str = Field(default="sse", description="Transport type: sse, stdio, http")
    auth_token: str | None = Field(default=None, description="Authentication token")


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


class AnalysisFinding(BaseModel):
    """A finding from direct analysis."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Finding description")
    severity: Severity = Field(..., description="Severity level")
    category: AttackCategory = Field(..., description="Attack category")
    confidence: float = Field(default=1.0, description="Confidence score")
    evidence: dict[str, Any] | None = Field(default=None, description="Evidence data")
    remediation: str | None = Field(default=None, description="Remediation guidance")


class AnalysisResponse(BaseModel):
    """Response from direct analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(..., description="Analysis ID")
    status: str = Field(..., description="Analysis status")
    component_type: str = Field(..., description="Component type analyzed")
    findings: list[AnalysisFinding] = Field(..., description="Discovered findings")
    summary: dict[str, int] = Field(..., description="Findings summary by severity")
    duration_seconds: float = Field(..., description="Analysis duration")


@router.post(
    "/model",
    response_model=AnalysisResponse,
    summary="Analyze model",
    description="Analyze an LLM model for vulnerabilities.",
)
async def analyze_model(
    request: ModelAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze an LLM model for security vulnerabilities.

    Tests the model against various attack categories including:
    - Prompt injection
    - Jailbreaks
    - Data leakage
    - Harmful content generation
    """
    import uuid

    # TODO: Implement actual model analysis using probes/detectors
    # For now, return a placeholder response

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="model",
        findings=[],  # TODO: Run probes and return actual findings
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
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
    """Analyze context content (system prompts, personas, skills).

    Checks for:
    - Injection vulnerabilities
    - Sensitive information exposure
    - Excessive permissions
    - Output handling issues
    """
    import uuid

    # TODO: Implement actual context analysis

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="context",
        findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
    )


@router.post(
    "/mcp",
    response_model=AnalysisResponse,
    summary="Analyze MCP server",
    description="Analyze an MCP server for vulnerabilities.",
)
async def analyze_mcp(
    request: MCPAnalysisRequest,
    tenant: CurrentTenantDep,
) -> AnalysisResponse:
    """Analyze an MCP server for security vulnerabilities.

    Tests for:
    - Tool description injection
    - Data exfiltration capabilities
    - Privilege escalation
    - Rug-pull patterns (delayed malicious activation)
    """
    import uuid

    # TODO: Implement actual MCP analysis

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="mcp_server",
        findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
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
    """Analyze application code for AI security issues.

    Checks for:
    - Exposed API keys and secrets
    - Insecure model configurations
    - Injection vulnerabilities
    - Supply chain risks
    """
    import uuid

    if not request.content and not request.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either content or file_path must be provided",
        )

    # TODO: Implement actual code analysis

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="code",
        findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
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
    """Analyze an agentic workflow for security vulnerabilities.

    Supports frameworks:
    - LangChain
    - LangGraph
    - CrewAI
    - AutoGen
    - OpenAI Agents SDK

    Checks for:
    - Excessive agency
    - Tool chaining attacks
    - Privilege escalation paths
    - Data flow vulnerabilities
    """
    import uuid

    # TODO: Implement actual workflow analysis

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="workflow",
        findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
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
    """Analyze a model file for security issues.

    Checks for:
    - Pickle deserialization attacks
    - Malicious code in model weights
    - Supply chain verification
    - Hash verification
    """
    import uuid

    # Check file size (limit to 10GB)
    max_size = 10 * 1024 * 1024 * 1024  # 10GB
    file_size = 0

    # Read file in chunks to check size
    content = await file.read()
    file_size = len(content)

    if file_size > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large. Maximum size is 10GB.",
        )

    # TODO: Implement actual model file scanning

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        component_type="model_file",
        findings=[],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        duration_seconds=0.0,
    )
