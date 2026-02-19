"""MCP server security analyzer.

Main analyzer for MCP (Model Context Protocol) servers.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity

logger = logging.getLogger(__name__)


class MCPRiskCategory(str, Enum):
    """Categories of MCP security risks."""
    TOOL_INJECTION = "tool_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RUG_PULL = "rug_pull"
    RESOURCE_ABUSE = "resource_abuse"
    UNSAFE_EXECUTION = "unsafe_execution"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SCHEMA_VIOLATION = "schema_violation"
    PROMPT_INJECTION = "prompt_injection"
    SHADOW_WORKSPACE = "shadow_workspace"
    CROSS_ORIGIN = "cross_origin"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class MCPServerInfo:
    """Information about an MCP server."""
    name: str
    command: str | None = None
    url: str | None = None
    server_type: str = "unknown"  # stdio, sse, http
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "command": self.command,
            "url": self.url,
            "server_type": self.server_type,
            "tools": self.tools,
            "resources": self.resources,
            "prompts": self.prompts,
            "config": self.config,
        }


@dataclass
class MCPFinding:
    """A security finding in an MCP server."""
    category: MCPRiskCategory
    severity: Severity
    title: str
    description: str
    server_name: str
    tool_name: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class MCPAnalysisResult:
    """Result of MCP server analysis."""
    server_info: MCPServerInfo
    findings: list[MCPFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if no security issues were found."""
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_category(self, category: MCPRiskCategory) -> list[MCPFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]


# Risk patterns for MCP tool descriptions
TOOL_DESCRIPTION_RISKS = [
    {
        "pattern": r"(ignore|bypass|override)\s+(\w+\s+)*(instructions?|rules?|guidelines?)",
        "category": MCPRiskCategory.PROMPT_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Instruction override in tool description",
        "description": "Tool description attempts to override AI instructions",
    },
    {
        "pattern": r"(admin|root|sudo|elevated)\s+(access|privileges?|permissions?)",
        "category": MCPRiskCategory.PRIVILEGE_ESCALATION,
        "severity": Severity.HIGH,
        "title": "Privilege escalation in tool description",
        "description": "Tool claims elevated privileges",
    },
    {
        "pattern": r"(send|transmit|upload|exfiltrate)\s+(data|files?|information)",
        "category": MCPRiskCategory.DATA_EXFILTRATION,
        "severity": Severity.HIGH,
        "title": "Data exfiltration in tool description",
        "description": "Tool description mentions data transmission",
    },
    {
        "pattern": r"(execute|run|eval)\s+(any|arbitrary|code|commands?)",
        "category": MCPRiskCategory.UNSAFE_EXECUTION,
        "severity": Severity.CRITICAL,
        "title": "Arbitrary execution in tool description",
        "description": "Tool allows arbitrary code execution",
    },
    {
        "pattern": r"(hidden|secret|covert|stealth)",
        "category": MCPRiskCategory.RUG_PULL,
        "severity": Severity.MEDIUM,
        "title": "Hidden functionality indicated",
        "description": "Tool description mentions hidden or covert behavior",
    },
]


class MCPAnalyzer:
    """Analyzes MCP servers for security vulnerabilities.

    Checks:
    - Tool description injection attacks
    - Data exfiltration patterns
    - Privilege escalation attempts
    - Rug pull / delayed activation
    - Schema violations
    - Configuration issues
    """

    def __init__(self):
        """Initialize MCP analyzer."""
        # Compile risk patterns
        self._risk_patterns = [
            {
                **risk,
                "compiled": re.compile(risk["pattern"], re.IGNORECASE),
            }
            for risk in TOOL_DESCRIPTION_RISKS
        ]

    def analyze_config_file(self, config_path: Path | str) -> list[MCPAnalysisResult]:
        """Analyze MCP configuration file.

        Args:
            config_path: Path to .mcp.json or mcp_config.json file.

        Returns:
            List of analysis results for each server.
        """
        config_path = Path(config_path)

        if not config_path.exists():
            return []

        try:
            config = json.loads(config_path.read_text())
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {config_path}: {e}")
            return []

        results = []

        # Parse servers from config
        servers = config.get("mcpServers", config.get("servers", {}))

        for name, server_config in servers.items():
            server_info = self._parse_server_config(name, server_config)
            result = self.analyze_server(server_info)

            # Also check config-level issues
            config_findings = list(self._check_config(name, server_config))
            result.findings.extend(config_findings)

            results.append(result)

        return results

    def _parse_server_config(
        self,
        name: str,
        config: dict[str, Any],
    ) -> MCPServerInfo:
        """Parse server configuration.

        Args:
            name: Server name.
            config: Server configuration dict.

        Returns:
            MCPServerInfo object.
        """
        command = config.get("command")
        url = config.get("url")

        # Determine server type
        if command:
            server_type = "stdio"
        elif url:
            if "sse" in url.lower():
                server_type = "sse"
            else:
                server_type = "http"
        else:
            server_type = "unknown"

        return MCPServerInfo(
            name=name,
            command=command,
            url=url,
            server_type=server_type,
            config=config,
        )

    def analyze_server(self, server_info: MCPServerInfo) -> MCPAnalysisResult:
        """Analyze an MCP server.

        Args:
            server_info: Server information.

        Returns:
            Analysis result.
        """
        result = MCPAnalysisResult(server_info=server_info)

        # Analyze tools
        for tool in server_info.tools:
            tool_findings = list(self._analyze_tool(server_info.name, tool))
            result.findings.extend(tool_findings)

        # Analyze resources
        for resource in server_info.resources:
            resource_findings = list(self._analyze_resource(server_info.name, resource))
            result.findings.extend(resource_findings)

        # Analyze prompts
        for prompt in server_info.prompts:
            prompt_findings = list(self._analyze_prompt(server_info.name, prompt))
            result.findings.extend(prompt_findings)

        # Check command/URL safety
        if server_info.command:
            cmd_findings = list(self._check_command(server_info.name, server_info.command))
            result.findings.extend(cmd_findings)

        if server_info.url:
            url_findings = list(self._check_url(server_info.name, server_info.url))
            result.findings.extend(url_findings)

        return result

    def _analyze_tool(
        self,
        server_name: str,
        tool: dict[str, Any],
    ) -> Iterator[MCPFinding]:
        """Analyze a tool definition.

        Args:
            server_name: Server name.
            tool: Tool definition.

        Yields:
            Security findings.
        """
        tool_name = tool.get("name", "unknown")
        description = tool.get("description", "")

        # Check description for risk patterns
        for risk in self._risk_patterns:
            if risk["compiled"].search(description):
                yield MCPFinding(
                    category=risk["category"],
                    severity=risk["severity"],
                    title=risk["title"],
                    description=risk["description"],
                    server_name=server_name,
                    tool_name=tool_name,
                    evidence={"description_excerpt": description[:200]},
                    remediation="Review and sanitize tool description",
                )

        # Check for dangerous tool names.
        # Exact-match names that are always dangerous:
        _exact_dangerous = {
            "exec", "eval", "shell", "cmd", "sudo", "rm",
        }
        # Word-boundary names that are only dangerous when they appear as
        # standalone words (separated by _, -, or word boundaries) to avoid
        # matching "format_output", "system_info", "runtime", etc.
        _boundary_dangerous = re.compile(
            r"(?:^|[_\-])(?:system|run|delete|admin|root|format)(?:$|[_\-])",
            re.IGNORECASE,
        )
        name_lower = tool_name.lower()
        is_dangerous = (
            name_lower in _exact_dangerous
            or _boundary_dangerous.search(name_lower)
        )
        if is_dangerous:
            yield MCPFinding(
                category=MCPRiskCategory.UNSAFE_EXECUTION,
                severity=Severity.MEDIUM,
                title=f"Potentially dangerous tool name: {tool_name}",
                description="Tool name suggests dangerous operations",
                server_name=server_name,
                tool_name=tool_name,
                remediation="Review tool functionality carefully",
            )

        # Check input schema for issues
        input_schema = tool.get("inputSchema", {})
        if input_schema:
            yield from self._check_schema(server_name, tool_name, input_schema)

    def _analyze_resource(
        self,
        server_name: str,
        resource: dict[str, Any],
    ) -> Iterator[MCPFinding]:
        """Analyze a resource definition.

        Args:
            server_name: Server name.
            resource: Resource definition.

        Yields:
            Security findings.
        """
        uri = resource.get("uri", "")
        description = resource.get("description", "")

        # Check for sensitive paths
        sensitive_patterns = [
            (r"/etc/passwd", "System password file"),
            (r"/etc/shadow", "System shadow file"),
            (r"~/.ssh", "SSH directory"),
            (r"\.env", "Environment file"),
            (r"credentials", "Credentials file"),
            (r"secret", "Secret file"),
            (r"/proc/", "Proc filesystem"),
        ]

        for pattern, desc in sensitive_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                yield MCPFinding(
                    category=MCPRiskCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.HIGH,
                    title=f"Sensitive resource access: {desc}",
                    description=f"Resource URI may expose sensitive data: {uri}",
                    server_name=server_name,
                    evidence={"uri": uri},
                    remediation="Restrict access to sensitive resources",
                )

    def _analyze_prompt(
        self,
        server_name: str,
        prompt: dict[str, Any],
    ) -> Iterator[MCPFinding]:
        """Analyze a prompt definition.

        Args:
            server_name: Server name.
            prompt: Prompt definition.

        Yields:
            Security findings.
        """
        description = prompt.get("description", "")

        # Check description for risk patterns
        for risk in self._risk_patterns:
            if risk["compiled"].search(description):
                yield MCPFinding(
                    category=risk["category"],
                    severity=risk["severity"],
                    title=f"Risky prompt: {risk['title']}",
                    description=risk["description"],
                    server_name=server_name,
                    evidence={"description_excerpt": description[:200]},
                    remediation="Review and sanitize prompt description",
                )

    def _check_schema(
        self,
        server_name: str,
        tool_name: str,
        schema: dict[str, Any],
    ) -> Iterator[MCPFinding]:
        """Check tool input schema for issues.

        Args:
            server_name: Server name.
            tool_name: Tool name.
            schema: Input schema.

        Yields:
            Security findings.
        """
        properties = schema.get("properties", {})

        for prop_name, prop_def in properties.items():
            # Check for dangerous property names
            dangerous_props = ["command", "code", "script", "exec", "eval", "query"]
            if prop_name.lower() in dangerous_props:
                yield MCPFinding(
                    category=MCPRiskCategory.UNSAFE_EXECUTION,
                    severity=Severity.MEDIUM,
                    title=f"Dangerous input property: {prop_name}",
                    description="Input schema accepts potentially dangerous input",
                    server_name=server_name,
                    tool_name=tool_name,
                    evidence={"property": prop_name, "schema": prop_def},
                    remediation="Validate and sanitize this input carefully",
                )

    def _check_command(
        self,
        server_name: str,
        command: str,
    ) -> Iterator[MCPFinding]:
        """Check server command for issues.

        Args:
            server_name: Server name.
            command: Server command.

        Yields:
            Security findings.
        """
        # Check for dangerous commands
        dangerous_commands = [
            ("curl", "Downloads content from external URLs"),
            ("wget", "Downloads content from external URLs"),
            ("nc", "Netcat - network tool"),
            ("bash -c", "Shell execution"),
            ("sh -c", "Shell execution"),
            ("python -c", "Python code execution"),
            ("node -e", "Node.js code execution"),
        ]

        for dangerous, desc in dangerous_commands:
            if dangerous in command.lower():
                yield MCPFinding(
                    category=MCPRiskCategory.UNSAFE_EXECUTION,
                    severity=Severity.MEDIUM,
                    title=f"Potentially dangerous command: {dangerous}",
                    description=desc,
                    server_name=server_name,
                    evidence={"command": command},
                    remediation="Review command and ensure it's necessary",
                )

        # Check for hardcoded secrets
        secret_patterns = [
            (r"['\"]?[a-zA-Z_]*(?:key|token|secret|password|api)['\"]?\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}", "Hardcoded secret"),
        ]

        for pattern, desc in secret_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                yield MCPFinding(
                    category=MCPRiskCategory.AUTHENTICATION,
                    severity=Severity.CRITICAL,
                    title="Hardcoded secret in command",
                    description="Command contains hardcoded credentials",
                    server_name=server_name,
                    remediation="Use environment variables for secrets",
                )

    def _check_url(
        self,
        server_name: str,
        url: str,
    ) -> Iterator[MCPFinding]:
        """Check server URL for issues.

        Args:
            server_name: Server name.
            url: Server URL.

        Yields:
            Security findings.
        """
        # Check for HTTP (non-HTTPS)
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            yield MCPFinding(
                category=MCPRiskCategory.CONFIGURATION,
                severity=Severity.MEDIUM,
                title="Insecure HTTP connection",
                description="MCP server uses unencrypted HTTP",
                server_name=server_name,
                evidence={"url": url},
                remediation="Use HTTPS for remote connections",
            )

        # Check for suspicious domains
        suspicious_domains = [
            "ngrok.io",
            "localhost.run",
            "serveo.net",
            "localtunnel.me",
        ]

        for domain in suspicious_domains:
            if domain in url:
                yield MCPFinding(
                    category=MCPRiskCategory.CROSS_ORIGIN,
                    severity=Severity.MEDIUM,
                    title=f"Tunnel service in use: {domain}",
                    description="MCP server uses a tunnel service",
                    server_name=server_name,
                    evidence={"url": url, "service": domain},
                    remediation="Verify the tunnel endpoint is trusted",
                )

    def _check_config(
        self,
        server_name: str,
        config: dict[str, Any],
    ) -> Iterator[MCPFinding]:
        """Check server configuration for issues.

        Args:
            server_name: Server name.
            config: Server configuration.

        Yields:
            Security findings.
        """
        # Check for disabled security features
        if config.get("skipVerification", False):
            yield MCPFinding(
                category=MCPRiskCategory.CONFIGURATION,
                severity=Severity.HIGH,
                title="Verification disabled",
                description="Server verification is disabled",
                server_name=server_name,
                remediation="Enable server verification",
            )

        # Check for auto-approve settings
        if config.get("autoApprove", []):
            yield MCPFinding(
                category=MCPRiskCategory.CONFIGURATION,
                severity=Severity.MEDIUM,
                title="Auto-approve enabled",
                description="Some tools are auto-approved without user consent",
                server_name=server_name,
                evidence={"auto_approve": config.get("autoApprove")},
                remediation="Review auto-approved tools carefully",
            )

        # Check environment variables for secrets
        env_vars = config.get("env", {})
        for key, value in env_vars.items():
            if isinstance(value, str) and len(value) > 20:
                key_lower = key.lower()
                if any(s in key_lower for s in ["key", "token", "secret", "password"]):
                    # Value might be a secret
                    yield MCPFinding(
                        category=MCPRiskCategory.AUTHENTICATION,
                        severity=Severity.LOW,
                        title=f"Potential secret in env var: {key}",
                        description="Environment variable may contain a secret",
                        server_name=server_name,
                        evidence={"variable": key},
                        remediation="Ensure secrets are properly managed",
                    )
