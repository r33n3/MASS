"""MCP tool schema analysis.

Analyzes MCP tool schemas for security issues.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.mcp.analyzer import MCPFinding, MCPRiskCategory


class SchemaIssue(str, Enum):
    """Types of schema issues."""
    MISSING_VALIDATION = "missing_validation"
    DANGEROUS_PATTERN = "dangerous_pattern"
    OVERLY_PERMISSIVE = "overly_permissive"
    TYPE_MISMATCH = "type_mismatch"
    INJECTION_RISK = "injection_risk"


@dataclass
class ToolSchema:
    """MCP tool schema representation."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolSchema":
        """Create from dictionary.

        Args:
            data: Dictionary representation.

        Returns:
            ToolSchema instance.
        """
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            input_schema=data.get("inputSchema", {}),
            output_schema=data.get("outputSchema"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class SchemaFinding:
    """Finding from schema analysis."""
    issue: SchemaIssue
    severity: Severity
    title: str
    description: str
    property_path: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None


class SchemaAnalyzer:
    """Analyzes MCP tool schemas for security issues.

    Checks:
    - Missing input validation
    - Dangerous property patterns
    - Overly permissive schemas
    - Injection risks in strings
    """

    def __init__(self):
        """Initialize schema analyzer."""
        # Dangerous property names
        self._dangerous_props = {
            "command": (Severity.HIGH, "Command execution input"),
            "cmd": (Severity.HIGH, "Command execution input"),
            "code": (Severity.HIGH, "Code execution input"),
            "script": (Severity.HIGH, "Script execution input"),
            "exec": (Severity.CRITICAL, "Execution input"),
            "eval": (Severity.CRITICAL, "Eval input"),
            "query": (Severity.MEDIUM, "Query input (potential injection)"),
            "sql": (Severity.HIGH, "SQL input (potential injection)"),
            "shell": (Severity.CRITICAL, "Shell input"),
            "bash": (Severity.CRITICAL, "Bash input"),
            "path": (Severity.MEDIUM, "Path input (potential traversal)"),
            "file": (Severity.MEDIUM, "File input"),
            "url": (Severity.MEDIUM, "URL input"),
            "password": (Severity.HIGH, "Password input (sensitive)"),
            "secret": (Severity.HIGH, "Secret input (sensitive)"),
            "token": (Severity.HIGH, "Token input (sensitive)"),
        }

        # Dangerous patterns in descriptions
        self._desc_patterns = [
            (r"(execute|run)\s+(any|arbitrary)", Severity.CRITICAL, "Arbitrary execution"),
            (r"(no|without)\s+(validation|sanitization)", Severity.HIGH, "No input validation"),
            (r"(admin|root|sudo)\s+(access|privileges?)", Severity.HIGH, "Elevated privileges"),
            (r"(bypass|ignore)\s+(safety|security)", Severity.CRITICAL, "Security bypass"),
        ]

    def analyze_tool(self, tool: ToolSchema | dict[str, Any]) -> list[SchemaFinding]:
        """Analyze a tool schema.

        Args:
            tool: Tool schema or dictionary.

        Returns:
            List of findings.
        """
        if isinstance(tool, dict):
            tool = ToolSchema.from_dict(tool)

        findings = []

        # Analyze description
        findings.extend(self._analyze_description(tool))

        # Analyze input schema
        if tool.input_schema:
            findings.extend(self._analyze_input_schema(tool))

        return findings

    def analyze_tools(
        self,
        tools: list[ToolSchema | dict[str, Any]],
    ) -> dict[str, list[SchemaFinding]]:
        """Analyze multiple tool schemas.

        Args:
            tools: List of tool schemas.

        Returns:
            Dictionary mapping tool names to findings.
        """
        results = {}

        for tool in tools:
            if isinstance(tool, dict):
                tool = ToolSchema.from_dict(tool)

            findings = self.analyze_tool(tool)
            if findings:
                results[tool.name] = findings

        return results

    def _analyze_description(self, tool: ToolSchema) -> Iterator[SchemaFinding]:
        """Analyze tool description.

        Args:
            tool: Tool schema.

        Yields:
            Description findings.
        """
        desc = tool.description.lower()

        for pattern, severity, issue_name in self._desc_patterns:
            if re.search(pattern, desc, re.IGNORECASE):
                yield SchemaFinding(
                    issue=SchemaIssue.DANGEROUS_PATTERN,
                    severity=severity,
                    title=f"Dangerous description pattern: {issue_name}",
                    description=f"Tool '{tool.name}' description indicates {issue_name}",
                    evidence={"pattern": pattern},
                    remediation="Review and restrict tool functionality",
                )

    def _analyze_input_schema(self, tool: ToolSchema) -> Iterator[SchemaFinding]:
        """Analyze input schema.

        Args:
            tool: Tool schema.

        Yields:
            Input schema findings.
        """
        schema = tool.input_schema

        # Check if schema has properties
        properties = schema.get("properties", {})

        if not properties and schema.get("type") == "object":
            # Schema allows any properties
            yield SchemaFinding(
                issue=SchemaIssue.OVERLY_PERMISSIVE,
                severity=Severity.MEDIUM,
                title="Schema allows arbitrary properties",
                description=f"Tool '{tool.name}' accepts any input properties",
                remediation="Define explicit properties in schema",
            )

        # Check additionalProperties
        if schema.get("additionalProperties", True) and properties:
            yield SchemaFinding(
                issue=SchemaIssue.OVERLY_PERMISSIVE,
                severity=Severity.LOW,
                title="Schema allows additional properties",
                description=f"Tool '{tool.name}' allows undefined properties",
                remediation="Set additionalProperties: false",
            )

        # Analyze each property
        for prop_name, prop_def in properties.items():
            yield from self._analyze_property(tool.name, prop_name, prop_def)

    def _analyze_property(
        self,
        tool_name: str,
        prop_name: str,
        prop_def: dict[str, Any],
        path: str = "",
    ) -> Iterator[SchemaFinding]:
        """Analyze a property definition.

        Args:
            tool_name: Tool name.
            prop_name: Property name.
            prop_def: Property definition.
            path: JSON path to property.

        Yields:
            Property findings.
        """
        full_path = f"{path}.{prop_name}" if path else prop_name
        prop_name_lower = prop_name.lower()

        # Check for dangerous property names
        for dangerous, (severity, desc) in self._dangerous_props.items():
            if dangerous in prop_name_lower:
                yield SchemaFinding(
                    issue=SchemaIssue.DANGEROUS_PATTERN,
                    severity=severity,
                    title=f"Dangerous property: {prop_name}",
                    description=f"Tool '{tool_name}' has {desc}",
                    property_path=full_path,
                    remediation="Validate and sanitize this input carefully",
                )
                break

        # Check property type
        prop_type = prop_def.get("type")

        if prop_type == "string":
            yield from self._check_string_property(tool_name, prop_name, prop_def, full_path)
        elif prop_type == "array":
            yield from self._check_array_property(tool_name, prop_name, prop_def, full_path)
        elif prop_type == "object":
            # Recurse into nested properties
            nested_props = prop_def.get("properties", {})
            for nested_name, nested_def in nested_props.items():
                yield from self._analyze_property(
                    tool_name, nested_name, nested_def, full_path
                )

    def _check_string_property(
        self,
        tool_name: str,
        prop_name: str,
        prop_def: dict[str, Any],
        path: str,
    ) -> Iterator[SchemaFinding]:
        """Check string property for issues.

        Args:
            tool_name: Tool name.
            prop_name: Property name.
            prop_def: Property definition.
            path: Property path.

        Yields:
            String property findings.
        """
        # Check for missing constraints
        has_constraints = any(
            k in prop_def
            for k in ["pattern", "maxLength", "enum", "format"]
        )

        prop_name_lower = prop_name.lower()

        # High-risk string properties without constraints
        high_risk_names = ["command", "code", "script", "query", "path", "url"]
        is_high_risk = any(r in prop_name_lower for r in high_risk_names)

        if is_high_risk and not has_constraints:
            yield SchemaFinding(
                issue=SchemaIssue.MISSING_VALIDATION,
                severity=Severity.MEDIUM,
                title=f"Unconstrained high-risk string: {prop_name}",
                description=f"Tool '{tool_name}' property '{prop_name}' has no validation constraints",
                property_path=path,
                remediation="Add pattern, maxLength, or enum constraints",
            )

        # Check description for injection hints
        desc = prop_def.get("description", "").lower()
        injection_hints = ["inject", "execute", "raw", "unescaped", "unsafe"]
        if any(hint in desc for hint in injection_hints):
            yield SchemaFinding(
                issue=SchemaIssue.INJECTION_RISK,
                severity=Severity.HIGH,
                title=f"Potential injection risk: {prop_name}",
                description=f"Property description suggests injection risk",
                property_path=path,
                evidence={"description": prop_def.get("description")},
                remediation="Review property usage for injection vulnerabilities",
            )

    def _check_array_property(
        self,
        tool_name: str,
        prop_name: str,
        prop_def: dict[str, Any],
        path: str,
    ) -> Iterator[SchemaFinding]:
        """Check array property for issues.

        Args:
            tool_name: Tool name.
            prop_name: Property name.
            prop_def: Property definition.
            path: Property path.

        Yields:
            Array property findings.
        """
        # Check for missing items constraint
        if "items" not in prop_def:
            yield SchemaFinding(
                issue=SchemaIssue.MISSING_VALIDATION,
                severity=Severity.LOW,
                title=f"Array without items schema: {prop_name}",
                description=f"Tool '{tool_name}' array property has no items schema",
                property_path=path,
                remediation="Define items schema for array",
            )

        # Check for missing maxItems
        if "maxItems" not in prop_def:
            yield SchemaFinding(
                issue=SchemaIssue.OVERLY_PERMISSIVE,
                severity=Severity.LOW,
                title=f"Array without maxItems: {prop_name}",
                description=f"Tool '{tool_name}' array has no maximum length",
                property_path=path,
                remediation="Add maxItems constraint to prevent DoS",
            )

        # Analyze items schema
        items_schema = prop_def.get("items", {})
        if items_schema.get("type") == "string":
            yield from self._check_string_property(
                tool_name, f"{prop_name}[]", items_schema, f"{path}[]"
            )

    def convert_to_mcp_findings(
        self,
        schema_findings: list[SchemaFinding],
        server_name: str,
        tool_name: str,
    ) -> list[MCPFinding]:
        """Convert schema findings to MCP findings.

        Args:
            schema_findings: List of schema findings.
            server_name: Server name.
            tool_name: Tool name.

        Returns:
            List of MCP findings.
        """
        mcp_findings = []

        for sf in schema_findings:
            mcp_findings.append(MCPFinding(
                category=MCPRiskCategory.SCHEMA_VIOLATION,
                severity=sf.severity,
                title=sf.title,
                description=sf.description,
                server_name=server_name,
                tool_name=tool_name,
                evidence={
                    "issue_type": sf.issue.value,
                    "property_path": sf.property_path,
                    **sf.evidence,
                },
                remediation=sf.remediation,
            ))

        return mcp_findings
