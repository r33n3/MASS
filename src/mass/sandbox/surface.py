"""Target-surface discovery for corpus-based sandbox testing.

Given a target type and configuration, discovers what can be tested:
tools, model endpoints, and instruction sets.  Each discovery result
feeds into the :class:`CorpusBinder` which binds attack payloads to
the discovered surface.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Surface dataclasses ──────────────────────────────────────────────


@dataclass
class ToolSurface:
    """A discovered tool that can be tested."""

    name: str
    description: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    input_schema: dict[str, Any] | None = None
    source: str = ""  # mcp, architecture_map, skill_file

    # MCP connection info — populated only when the tool can be called live
    mcp_config: dict[str, Any] | None = None

    # Instructions/rules extracted from the same source (e.g. skill file docstrings)
    source_rules: list[str] = field(default_factory=list)


@dataclass
class ModelSurface:
    """A discovered model endpoint to test."""

    provider: str
    model: str
    endpoint: str = ""
    api_key: str = ""
    source: str = ""  # model_endpoint, model_file, platform_default


@dataclass
class InstructionSurface:
    """A discovered instruction / system prompt to test."""

    content: str
    source: str = ""  # instruction_file, architecture_map, deployment
    rules: list[str] = field(default_factory=list)


@dataclass
class TargetSurface:
    """Aggregate surface discovered from a target."""

    tools: list[ToolSurface] = field(default_factory=list)
    models: list[ModelSurface] = field(default_factory=list)
    instructions: list[InstructionSurface] = field(default_factory=list)


# ── Main discovery function ──────────────────────────────────────────


async def discover_surface(
    target_type: str,
    *,
    # MCP config
    mcp_url: str | None = None,
    mcp_transport: str = "http",
    mcp_command: str | None = None,
    mcp_args: list[str] | None = None,
    mcp_headers: dict[str, str] | None = None,
    mcp_env: dict[str, str] | None = None,
    # File-based
    file_path: str | None = None,
    # Architecture map / deployment
    deployment_id: str | None = None,
    db_session: Any | None = None,
    # Model endpoint
    model_provider: str | None = None,
    model_name: str | None = None,
    model_endpoint: str | None = None,
    model_api_key: str | None = None,
    # Browser agent
    browser_config: dict[str, Any] | None = None,
) -> TargetSurface:
    """Discover testable surface for any target type.

    Returns a :class:`TargetSurface` containing tools, models, and
    instructions that the :class:`CorpusBinder` will bind payloads to.
    """

    if target_type == "mcp_server":
        return await _discover_mcp(
            mcp_url=mcp_url,
            mcp_transport=mcp_transport,
            mcp_command=mcp_command,
            mcp_args=mcp_args,
            mcp_headers=mcp_headers,
            mcp_env=mcp_env,
        )

    if target_type == "deployment":
        return await _discover_deployment(
            deployment_id=deployment_id,
            db_session=db_session,
            model_provider=model_provider,
            model_name=model_name,
        )

    if target_type == "model_endpoint":
        return _discover_model_endpoint(
            provider=model_provider,
            model=model_name,
            endpoint=model_endpoint,
            api_key=model_api_key,
        )

    if target_type == "model_file":
        return _discover_model_file(
            file_path=file_path,
            model_provider=model_provider,
            model_name=model_name,
            model_api_key=model_api_key,
        )

    if target_type == "instruction_file":
        return _discover_instruction_file(file_path=file_path)

    if target_type == "skill_file":
        # Support remote URLs — download to temp file first
        actual_path = file_path
        if file_path and file_path.startswith(("http://", "https://")):
            actual_path = await _download_remote_file(file_path)
        return _discover_skill_file(file_path=actual_path)

    if target_type == "agent_endpoint":
        return await _discover_agent_endpoint(
            mcp_url=mcp_url,
            mcp_transport=mcp_transport,
            mcp_command=mcp_command,
            mcp_args=mcp_args,
            mcp_headers=mcp_headers,
            mcp_env=mcp_env,
            model_provider=model_provider,
            model_name=model_name,
            model_endpoint=model_endpoint,
            model_api_key=model_api_key,
        )

    if target_type == "browser_agent":
        return await _discover_browser_agent(browser_config=browser_config)

    raise ValueError(f"Unsupported target type: {target_type}")


# ── Per-type discovery helpers ───────────────────────────────────────


async def _discover_mcp(
    *,
    mcp_url: str | None,
    mcp_transport: str,
    mcp_command: str | None,
    mcp_args: list[str] | None,
    mcp_headers: dict[str, str] | None,
    mcp_env: dict[str, str] | None,
) -> TargetSurface:
    """Discover tools via MCP server connection."""
    from mass.mcp.client import MCPClient
    from mass.mcp.stdio_bridge import StdioBridge

    bridge: StdioBridge | None = None
    effective_url = mcp_url or ""
    effective_transport = mcp_transport

    try:
        if mcp_transport == "stdio":
            if not mcp_command:
                raise ValueError("stdio transport requires a 'command'")
            bridge = StdioBridge(command=mcp_command, args=mcp_args or [])
            effective_url = await bridge.start()
            effective_transport = "http"

        client = _make_mcp_client(effective_transport, effective_url, mcp_headers or {})
        await client.connect()
        tools = await client.list_tools()
        await client.disconnect()
    finally:
        if bridge:
            await bridge.stop()

    mcp_config = {
        "url": effective_url,
        "transport": effective_transport,
        "command": mcp_command,
        "args": mcp_args or [],
        "headers": mcp_headers or {},
        "env": mcp_env or {},
    }

    tool_surfaces = [
        ToolSurface(
            name=t.name,
            description=t.description or "",
            parameters=[
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description or "",
                    "required": p.required,
                }
                for p in t.parameters
            ],
            input_schema=t.input_schema,
            source="mcp",
            mcp_config=mcp_config,
        )
        for t in tools
    ]

    logger.info("Discovered %d MCP tools", len(tool_surfaces))
    return TargetSurface(tools=tool_surfaces)


async def _discover_deployment(
    *,
    deployment_id: str | None,
    db_session: Any | None,
    model_provider: str | None,
    model_name: str | None,
) -> TargetSurface:
    """Discover tools + instructions from an ArchitectureMap in a deployment."""
    if not deployment_id:
        raise ValueError("deployment target requires deployment_id")

    from mass.analyzers.code.models import ArchitectureMap
    from mass.storage.repositories.deployment import DeploymentRepository

    if db_session is None:
        from mass.storage.database import get_session

        async with get_session() as session:
            return await _extract_architecture(
                session, deployment_id, model_provider, model_name,
            )

    return await _extract_architecture(
        db_session, deployment_id, model_provider, model_name,
    )


async def _extract_architecture(
    session: Any,
    deployment_id: str,
    model_provider: str | None,
    model_name: str | None,
) -> TargetSurface:
    from mass.analyzers.code.models import ArchitectureMap
    from mass.storage.repositories.deployment import DeploymentRepository

    repo = DeploymentRepository(session)
    deployment = await repo.get(deployment_id)
    if not deployment:
        raise ValueError(f"Deployment {deployment_id} not found")

    arch_data = None
    if deployment.meta:
        try:
            meta = json.loads(deployment.meta) if isinstance(deployment.meta, str) else deployment.meta
            arch_data = meta.get("architecture_map")
        except (json.JSONDecodeError, TypeError):
            pass

    if not arch_data:
        raise ValueError(f"No ArchitectureMap found for deployment {deployment_id}")

    arch = ArchitectureMap.from_dict(arch_data) if isinstance(arch_data, dict) else arch_data

    # Tools from tool_definitions
    tool_surfaces = [
        ToolSurface(
            name=td.name,
            description=td.purpose,
            parameters=[{"name": "input", "type": "string", "description": td.purpose, "required": True}],
            source="architecture_map",
        )
        for td in arch.tool_definitions
    ]

    # Models from model_connections
    model_surfaces = []
    for mc in arch.model_connections:
        model_surfaces.append(ModelSurface(
            provider=model_provider or mc.provider,
            model=model_name or mc.model_name or "",
            source="architecture_map",
        ))

    # Instructions from system prompts
    instruction_surfaces = []
    for mc in arch.model_connections:
        if mc.system_prompt_source:
            instruction_surfaces.append(InstructionSurface(
                content=mc.system_prompt_source,
                source="architecture_map",
                rules=_extract_rules(mc.system_prompt_source),
            ))

    logger.info(
        "Deployment %s: %d tools, %d models, %d instructions",
        deployment_id, len(tool_surfaces), len(model_surfaces), len(instruction_surfaces),
    )

    return TargetSurface(
        tools=tool_surfaces,
        models=model_surfaces,
        instructions=instruction_surfaces,
    )


def _discover_model_endpoint(
    *,
    provider: str | None,
    model: str | None,
    endpoint: str | None,
    api_key: str | None,
) -> TargetSurface:
    """Discover model from provided endpoint config."""
    from mass.api.utils.llm_config import resolve_llm_config

    cfg = resolve_llm_config(provider, model, api_key, endpoint)

    return TargetSurface(
        models=[ModelSurface(
            provider=cfg.provider,
            model=cfg.model,
            endpoint=cfg.endpoint,
            api_key=cfg.api_key,
            source="model_endpoint",
        )],
    )


def _discover_model_file(
    *,
    file_path: str | None,
    model_provider: str | None,
    model_name: str | None,
    model_api_key: str | None,
) -> TargetSurface:
    """For model_file targets, use the platform default model to test against."""
    from mass.api.utils.llm_config import resolve_llm_config

    cfg = resolve_llm_config(model_provider, model_name, model_api_key)

    return TargetSurface(
        models=[ModelSurface(
            provider=cfg.provider,
            model=cfg.model,
            endpoint=cfg.endpoint,
            api_key=cfg.api_key,
            source="model_file",
        )],
    )


def _discover_instruction_file(*, file_path: str | None) -> TargetSurface:
    """Read an instruction/system-prompt file."""
    if not file_path:
        raise ValueError("instruction_file target requires file_path")

    p = Path(file_path)
    if not p.is_file():
        raise ValueError(f"Instruction file not found: {file_path}")

    content = p.read_text(encoding="utf-8")
    rules = _extract_rules(content)

    return TargetSurface(
        instructions=[InstructionSurface(
            content=content,
            source="instruction_file",
            rules=rules,
        )],
    )


def _discover_skill_file(*, file_path: str | None) -> TargetSurface:
    """Parse a skill file (Python/JS/Markdown SKILL.md) for security surfaces."""
    if not file_path:
        raise ValueError("skill_file target requires file_path")

    p = Path(file_path)
    if not p.is_file():
        raise ValueError(f"Skill file not found: {file_path}")

    content = p.read_text(encoding="utf-8")

    # Route to appropriate parser
    if p.suffix == ".md":
        return _parse_skill_markdown(content, p.name)
    elif p.suffix == ".py":
        return _parse_skill_python(content, p.name)
    elif p.suffix in (".js", ".ts", ".mjs"):
        return _parse_skill_js(content, p.name)
    else:
        # Try markdown-style parsing for unknown extensions
        return _parse_skill_markdown(content, p.name)


def _parse_skill_markdown(content: str, filename: str) -> TargetSurface:
    """Parse a SKILL.md file for security-relevant surfaces.

    Supports both Claude Skills (comma-separated allowed-tools) and
    AgentSkills spec (space-delimited with patterns like Bash(git:*)).

    Extracts:
    - YAML frontmatter (name, description, allowed-tools, compatibility)
    - Code blocks as potential tool invocations
    - Instructions/rules from markdown body
    - URLs referenced in the content
    """
    tool_surfaces: list[ToolSurface] = []
    instruction_surfaces: list[InstructionSurface] = []

    # ── Parse YAML frontmatter ───────────────────────────────────
    frontmatter: dict = {}
    body = content
    fm_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if fm_match:
        fm_text = fm_match.group(1)
        body = content[fm_match.end():]
        # Simple YAML parser for top-level keys (handles metadata: block too)
        current_key = None
        for line in fm_text.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, _, val = line.partition(":")
                current_key = key.strip()
                frontmatter[current_key] = val.strip()
            elif current_key == "metadata" and line.startswith("  "):
                # Nested metadata key-value
                sub = line.strip()
                if ":" in sub:
                    sk, _, sv = sub.partition(":")
                    if "metadata" not in frontmatter or isinstance(frontmatter["metadata"], str):
                        frontmatter["metadata"] = {}
                    if isinstance(frontmatter["metadata"], dict):
                        frontmatter["metadata"][sk.strip()] = sv.strip().strip('"')

    skill_name = frontmatter.get("name", filename.replace(".md", ""))

    # ── Extract allowed-tools as tool surfaces ───────────────────
    # Supports both formats:
    #   Claude Skills:     "Bash,Read,Write"
    #   AgentSkills spec:  "Bash(git:*) Bash(jq:*) Read Write"
    allowed_tools_str = frontmatter.get("allowed-tools", "")
    if allowed_tools_str:
        # Detect format: comma-separated vs space-delimited
        if "," in allowed_tools_str:
            tool_tokens = [t.strip() for t in allowed_tools_str.split(",")]
        else:
            # Space-delimited — split on spaces but respect parentheses
            tool_tokens = re.findall(r'\S+(?:\([^)]*\))?', allowed_tools_str)

        for raw_tool in tool_tokens:
            if not raw_tool:
                continue
            # Parse AgentSkills pattern: Bash(git:*) → tool=Bash, scope=git:*
            pattern_match = re.match(r'^(\w+)(?:\(([^)]*)\))?$', raw_tool)
            if pattern_match:
                tool_base = pattern_match.group(1)
                tool_scope = pattern_match.group(2) or ""
                desc = f"Skill '{skill_name}' requests access to {tool_base}"
                if tool_scope:
                    desc += f" (scope: {tool_scope})"
            else:
                tool_base = raw_tool
                tool_scope = ""
                desc = f"Skill '{skill_name}' requests access to {raw_tool}"

            tool_surfaces.append(ToolSurface(
                name=tool_base,
                description=desc,
                parameters=[{
                    "name": "input",
                    "type": "string",
                    "description": f"Input passed to {tool_base} tool"
                    + (f" (scope: {tool_scope})" if tool_scope else ""),
                    "required": True,
                }],
                source="skill_file",
            ))

    # ── Extract compatibility as an instruction surface ──────────
    compatibility = frontmatter.get("compatibility", "")
    if compatibility:
        instruction_surfaces.append(InstructionSurface(
            content=f"Skill compatibility: {compatibility}",
            source="skill_file",
            rules=[f"IMPORTANT: {compatibility}"],
        ))

    # ── Extract code blocks as executable tool invocations ───────
    code_blocks = re.findall(r'```(\w*)\n(.*?)```', body, re.DOTALL)
    bash_commands: list[str] = []
    for lang, code in code_blocks:
        lang = lang.lower()
        if lang in ("bash", "sh", "shell", "zsh", ""):
            for line in code.strip().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    bash_commands.append(line)

        if lang in ("python", "python3", "py"):
            for match in re.finditer(
                r'(?:import|from)\s+(\S+)', code,
            ):
                module = match.group(1)
                if module not in ("os", "sys", "json", "re"):
                    continue
                bash_commands.append(f"python: import {module}")

    # Create a synthetic tool for bash execution if commands found
    if bash_commands:
        tool_surfaces.append(ToolSurface(
            name=f"{skill_name}_bash_execution",
            description=(
                f"Skill '{skill_name}' executes shell commands: "
                + "; ".join(bash_commands[:5])
                + ("..." if len(bash_commands) > 5 else "")
            ),
            parameters=[{
                "name": "command",
                "type": "string",
                "description": "Shell command to execute",
                "required": True,
            }],
            source="skill_file",
        ))

    # ── Extract URLs as potential network targets ────────────────
    urls = re.findall(r'https?://[^\s\)\"\'`>]+', body)
    unique_urls = list(dict.fromkeys(urls))  # preserve order, dedupe
    if unique_urls:
        tool_surfaces.append(ToolSurface(
            name=f"{skill_name}_network_access",
            description=(
                f"Skill '{skill_name}' references external URLs: "
                + ", ".join(unique_urls[:5])
                + ("..." if len(unique_urls) > 5 else "")
            ),
            parameters=[{
                "name": "url",
                "type": "string",
                "description": "URL accessed by the skill",
                "required": True,
            }],
            source="skill_file",
        ))

    # ── Extract instructions and rules ───────────────────────────
    all_rules = _extract_rules(body)

    # Extract markdown sections as instruction blocks
    sections = re.split(r'^#{1,3}\s+', body, flags=re.MULTILINE)
    for section in sections:
        section = section.strip()
        if len(section) < 20:
            continue
        section_rules = _extract_rules(section)
        if section_rules:
            instruction_surfaces.append(InstructionSurface(
                content=section[:500],
                source="skill_file",
                rules=section_rules,
            ))

    # If no section-level rules, use full body
    if not instruction_surfaces and all_rules:
        instruction_surfaces.append(InstructionSurface(
            content=body[:1000],
            source="skill_file",
            rules=all_rules,
        ))

    # Always include the skill description as an instruction surface
    description = frontmatter.get("description", "")
    if description:
        instruction_surfaces.append(InstructionSurface(
            content=description,
            source="skill_file",
            rules=[f"Skill purpose: {description}"],
        ))

    # Attach discovered rules to all tool surfaces so binder can include
    # them in the system prompt (tools and instructions are otherwise disjoint)
    if all_rules:
        for ts in tool_surfaces:
            if not ts.source_rules:
                ts.source_rules = list(all_rules)

    logger.info(
        "Skill markdown %s: %d tools, %d instruction blocks, %d bash commands, %d URLs",
        filename, len(tool_surfaces), len(instruction_surfaces),
        len(bash_commands), len(unique_urls),
    )

    return TargetSurface(tools=tool_surfaces, instructions=instruction_surfaces)


def _parse_skill_python(content: str, filename: str) -> TargetSurface:
    """Parse a Python skill file for function signatures as tools."""
    tool_surfaces: list[ToolSurface] = []

    for match in re.finditer(
        r'def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*\S+)?\s*:(?:\s*"""([^"]*?)""")?',
        content,
        re.DOTALL,
    ):
        name, params_str, docstring = match.groups()
        if name.startswith("_"):
            continue
        params = []
        for param in params_str.split(","):
            param = param.strip()
            if not param or param == "self" or param == "cls":
                continue
            param_name = param.split(":")[0].split("=")[0].strip()
            params.append({
                "name": param_name,
                "type": "string",
                "description": "",
                "required": "=" not in param,
            })
        # Extract rules from this function's docstring
        func_rules = _extract_rules(docstring) if docstring else []

        tool_surfaces.append(ToolSurface(
            name=name,
            description=(docstring or "").strip(),
            parameters=params,
            source="skill_file",
            source_rules=func_rules,
        ))

    instruction_surfaces: list[InstructionSurface] = []
    docstrings = re.findall(r'"""(.*?)"""', content, re.DOTALL)
    for ds in docstrings:
        rules = _extract_rules(ds)
        if rules:
            instruction_surfaces.append(InstructionSurface(
                content=ds.strip(),
                source="skill_file",
                rules=rules,
            ))

    logger.info(
        "Skill python %s: %d tools, %d instruction blocks",
        filename, len(tool_surfaces), len(instruction_surfaces),
    )

    return TargetSurface(tools=tool_surfaces, instructions=instruction_surfaces)


def _parse_skill_js(content: str, filename: str) -> TargetSurface:
    """Parse a JS/TS skill file for function signatures as tools."""
    tool_surfaces: list[ToolSurface] = []

    for match in re.finditer(
        r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
        content,
    ):
        name, params_str = match.groups()
        params = []
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue
            param_name = param.split(":")[0].split("=")[0].strip()
            params.append({
                "name": param_name,
                "type": "string",
                "description": "",
                "required": "=" not in param,
            })
        tool_surfaces.append(ToolSurface(
            name=name,
            description="",
            parameters=params,
            source="skill_file",
        ))

    instruction_surfaces: list[InstructionSurface] = []
    for ds in re.findall(r'/\*\*(.*?)\*/', content, re.DOTALL):
        rules = _extract_rules(ds)
        if rules:
            instruction_surfaces.append(InstructionSurface(
                content=ds.strip(),
                source="skill_file",
                rules=rules,
            ))

    # Attach global rules to tool surfaces (same pattern as markdown/python)
    all_rules_js = _extract_rules(content)
    if all_rules_js:
        for ts in tool_surfaces:
            if not ts.source_rules:
                ts.source_rules = list(all_rules_js)

    logger.info(
        "Skill JS %s: %d tools, %d instruction blocks",
        filename, len(tool_surfaces), len(instruction_surfaces),
    )

    return TargetSurface(tools=tool_surfaces, instructions=instruction_surfaces)


async def _discover_agent_endpoint(
    *,
    mcp_url: str | None,
    mcp_transport: str,
    mcp_command: str | None,
    mcp_args: list[str] | None,
    mcp_headers: dict[str, str] | None,
    mcp_env: dict[str, str] | None,
    model_provider: str | None,
    model_name: str | None,
    model_endpoint: str | None,
    model_api_key: str | None,
) -> TargetSurface:
    """Discover tools from agent + model endpoint config."""
    # Discover tools via MCP
    mcp_surface = await _discover_mcp(
        mcp_url=mcp_url,
        mcp_transport=mcp_transport,
        mcp_command=mcp_command,
        mcp_args=mcp_args,
        mcp_headers=mcp_headers,
        mcp_env=mcp_env,
    )

    # Discover model
    model_surface = _discover_model_endpoint(
        provider=model_provider,
        model=model_name,
        endpoint=model_endpoint,
        api_key=model_api_key,
    )

    return TargetSurface(
        tools=mcp_surface.tools,
        models=model_surface.models,
        instructions=mcp_surface.instructions,
    )


async def _discover_browser_agent(
    *,
    browser_config: dict[str, Any] | None,
) -> TargetSurface:
    """Discover capabilities of a browser-embedded chat agent.

    Probes the agent with discovery prompts to learn what it can do
    and what guardrails it has in place.
    """
    if not browser_config:
        raise ValueError("browser_agent target requires browser_config")

    from mass.runners.api.browser import BrowserRunner

    runner = BrowserRunner(
        url=browser_config["url"],
        input_selector=browser_config["input_selector"],
        output_selector=browser_config["output_selector"],
        send_selector=browser_config["send_selector"],
        wait_selector=browser_config.get("wait_selector"),
        headless=browser_config.get("headless", True),
        response_stabilize_ms=browser_config.get("response_stabilize_ms", 1500),
        timeout_ms=browser_config.get("timeout_ms", 30000),
        page_setup_steps=browser_config.get("page_setup_steps", []),
    )

    instruction_surfaces: list[InstructionSurface] = []
    tool_surfaces: list[ToolSurface] = []

    try:
        # Probe 1: What can you do?
        capabilities_result = await runner.run_async(
            "What can you help me with? Please list your main capabilities."
        )
        if capabilities_result.is_success and capabilities_result.response:
            instruction_surfaces.append(InstructionSurface(
                content=capabilities_result.response,
                source="browser_agent_probe",
                rules=[],
            ))
            # Extract any mentioned tools/actions from the response
            response_lower = capabilities_result.response.lower()
            capability_keywords = [
                ("search", "Search functionality"),
                ("file", "File access"),
                ("database", "Database queries"),
                ("email", "Email sending"),
                ("api", "API calls"),
                ("schedule", "Scheduling"),
                ("calculate", "Calculations"),
                ("translate", "Translation"),
                ("summarize", "Summarization"),
                ("analyze", "Analysis"),
            ]
            for keyword, desc in capability_keywords:
                if keyword in response_lower:
                    tool_surfaces.append(ToolSurface(
                        name=f"browser_agent_{keyword}",
                        description=f"Browser agent capability: {desc}",
                        parameters=[{
                            "name": "input",
                            "type": "string",
                            "description": f"Input for {desc.lower()}",
                            "required": True,
                        }],
                        source="browser_agent_probe",
                    ))

        # Probe 2: What are your guidelines/restrictions?
        guardrails_result = await runner.run_async(
            "What are your guidelines? What topics or requests are you not able to help with?"
        )
        if guardrails_result.is_success and guardrails_result.response:
            rules = _extract_rules(guardrails_result.response)
            instruction_surfaces.append(InstructionSurface(
                content=guardrails_result.response,
                source="browser_agent_guardrails",
                rules=rules,
            ))

    except Exception as e:
        logger.warning("Browser agent discovery probe failed: %s", e)
    finally:
        await runner.close()

    logger.info(
        "Browser agent: %d tools, %d instruction blocks discovered",
        len(tool_surfaces), len(instruction_surfaces),
    )

    return TargetSurface(
        tools=tool_surfaces,
        instructions=instruction_surfaces,
    )


# ── Utility ──────────────────────────────────────────────────────────


def _extract_rules(text: str) -> list[str]:
    """Extract explicit rules from instruction text.

    Looks for lines starting with NEVER, ALWAYS, DO NOT, MUST, etc.
    """
    rules: list[str] = []
    for line in text.splitlines():
        stripped = line.strip().lstrip("- ").lstrip("* ").strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if any(upper.startswith(kw) for kw in (
            "NEVER", "ALWAYS", "DO NOT", "DON'T", "MUST NOT",
            "MUST ", "YOU MUST", "YOU SHOULD NOT", "YOU CANNOT",
            "IMPORTANT:", "RULE:", "RESTRICTION:",
        )):
            rules.append(stripped)
    return rules


async def _download_remote_file(url: str) -> str:
    """Download a remote file to a temp path and return the local path."""
    import tempfile
    from urllib.parse import urlparse

    import httpx

    parsed = urlparse(url)
    # Infer filename from URL path
    path_parts = parsed.path.rstrip("/").split("/")
    filename = path_parts[-1] if path_parts else "SKILL.md"
    if not filename or "." not in filename:
        filename = "SKILL.md"

    # Convert GitHub tree URLs to raw content URLs
    raw_url = url
    if "github.com" in parsed.netloc and "/tree/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/tree/", "/")
        if not raw_url.endswith(".md"):
            raw_url = raw_url.rstrip("/") + "/SKILL.md"
    elif "github.com" in parsed.netloc and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    logger.info("Downloading skill file from %s", raw_url)

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        response = await client.get(raw_url)
        response.raise_for_status()

    # Write to temp file
    tmp = tempfile.NamedTemporaryFile(
        suffix=f"_{filename}", prefix="mass_skill_", delete=False, mode="w",
        encoding="utf-8",
    )
    tmp.write(response.text)
    tmp.close()

    logger.info("Downloaded %d bytes to %s", len(response.text), tmp.name)
    return tmp.name


def _make_mcp_client(transport: str, url: str, headers: dict[str, str]):
    """Create an MCPClient instance."""
    from mass.mcp.client import MCPClient

    if transport == "sse":
        return MCPClient.sse(sse_url=url, headers=headers)
    return MCPClient.http(base_url=url, headers=headers)
