"""Shared target validation and type mapping helpers.

Used by scan_targets, targets, and deployments routes to validate
target creation requests and infer deployment types.
"""

from fastapi import HTTPException, status

from mass.api.schemas.deployment import TargetType


def validate_target_type_requirements(
    target_type: TargetType,
    *,
    source_path: str | None = None,
    target_files: list[str] | None = None,
    content: str | None = None,
    mcp_servers: list | None = None,
    system_prompt: str | None = None,
    model_endpoint: str | None = None,
    model_provider: str | None = None,
    agent_url: str | None = None,
) -> None:
    """Validate that required fields are present for the given target type.

    Raises HTTPException 400 if validation fails.
    """
    if target_type == TargetType.DEPLOYMENT:
        if not source_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="source_path is required for deployment target type",
            )

    elif target_type == TargetType.MODEL_FILE:
        if not source_path and not target_files:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="source_path or target_files required for model_file target",
            )

    elif target_type == TargetType.MCP_SERVER:
        if not source_path and not content and not mcp_servers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide source_path, content, or mcp_servers for mcp_server target",
            )

    elif target_type == TargetType.SKILL_FILE:
        if not source_path and not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="source_path or content required for skill_file target",
            )

    elif target_type == TargetType.INSTRUCTION_FILE:
        if not source_path and not content and not system_prompt:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide source_path, content, or system_prompt for instruction_file target",
            )

    elif target_type == TargetType.MODEL_ENDPOINT:
        if not model_endpoint and not model_provider:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="model_endpoint or model_provider required for model_endpoint target",
            )

    elif target_type == TargetType.AGENT_ENDPOINT:
        if not agent_url and not model_endpoint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="agent_url or model_endpoint required for agent_endpoint target",
            )


def infer_deployment_type(target_type: TargetType) -> str:
    """Map a target type to the deployment_type column value.

    Returns:
        One of: "other", "agent", "api".
    """
    return {
        TargetType.DEPLOYMENT: "other",
        TargetType.MCP_SERVER: "other",
        TargetType.MODEL_FILE: "other",
        TargetType.SKILL_FILE: "agent",
        TargetType.INSTRUCTION_FILE: "other",
        TargetType.MODEL_ENDPOINT: "api",
        TargetType.AGENT_ENDPOINT: "agent",
    }.get(target_type, "other")
