"""Tool chaining attack patterns.

Detects patterns that enable tool chaining attacks.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from mass.core.types import Severity


@dataclass
class ToolChainingPattern:
    """Pattern for detecting tool chaining vulnerabilities."""
    name: str
    pattern: str | None
    severity: Severity
    description: str
    check_type: str  # config, tool_definition, interaction


# Tool chaining patterns
TOOL_CHAINING_PATTERNS = [
    ToolChainingPattern(
        name="unrestricted_tool_access",
        pattern=r"(tools?\s*[=:]\s*\*|all_tools\s*[=:]\s*true)",
        severity=Severity.CRITICAL,
        description="Agent has access to all tools without restriction",
        check_type="config",
    ),
    ToolChainingPattern(
        name="auto_approve_tools",
        pattern=r"(auto_approve|auto_execute)\s*[=:]\s*(true|\*|all)",
        severity=Severity.HIGH,
        description="Tool execution is auto-approved",
        check_type="config",
    ),
    ToolChainingPattern(
        name="recursive_tool_call",
        pattern=r"(allow_recursive|recursive_calls)\s*[=:]\s*true",
        severity=Severity.MEDIUM,
        description="Recursive tool calls are allowed",
        check_type="config",
    ),
    ToolChainingPattern(
        name="no_call_limit",
        pattern=r"(max_iterations|max_calls)\s*[=:]\s*(-1|unlimited|none)",
        severity=Severity.MEDIUM,
        description="No limit on tool call iterations",
        check_type="config",
    ),
    ToolChainingPattern(
        name="dangerous_tool_combination",
        pattern=None,  # Checked programmatically
        severity=Severity.HIGH,
        description="Dangerous combination of tools available",
        check_type="tool_definition",
    ),
    ToolChainingPattern(
        name="tool_output_not_sanitized",
        pattern=r"(raw_output|skip_sanitize)\s*[=:]\s*true",
        severity=Severity.HIGH,
        description="Tool outputs are not sanitized",
        check_type="config",
    ),
]


@dataclass
class ToolChainingFinding:
    """A tool chaining vulnerability finding."""
    pattern_name: str
    severity: Severity
    description: str
    tools_involved: list[str] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""


class ToolChainingDetector:
    """Detects tool chaining vulnerabilities.

    Analyzes:
    - Tool configurations and permissions
    - Tool combinations that enable attack chains
    - Missing safeguards in tool execution
    """

    # Dangerous tool combinations
    DANGEROUS_COMBINATIONS = [
        ({"read_file", "file_read"}, {"execute", "exec", "shell", "run_command"}),
        ({"search", "web_search"}, {"execute", "eval", "run_code"}),
        ({"database_query", "sql"}, {"file_write", "write_file"}),
        ({"api_call", "http_request"}, {"execute", "eval"}),
    ]

    def __init__(self, custom_patterns: list[ToolChainingPattern] | None = None):
        """Initialize detector.

        Args:
            custom_patterns: Additional patterns to use.
        """
        self.patterns = TOOL_CHAINING_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def analyze_config(
        self,
        config: dict[str, Any] | str,
    ) -> Iterator[ToolChainingFinding]:
        """Analyze tool configuration for chaining vulnerabilities.

        Args:
            config: Configuration dict or string.

        Yields:
            ToolChainingFinding for each issue.
        """
        if isinstance(config, dict):
            config_str = str(config)
        else:
            config_str = config

        for pattern in self.patterns:
            if pattern.check_type != "config" or not pattern.pattern:
                continue

            regex = re.compile(pattern.pattern, re.IGNORECASE)
            for match in regex.finditer(config_str):
                yield ToolChainingFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    evidence=match.group(0)[:200],
                    remediation=self._get_remediation(pattern.name),
                )

    def analyze_tools(
        self,
        tools: list[dict[str, Any]] | list[str],
    ) -> Iterator[ToolChainingFinding]:
        """Analyze tool definitions for chaining vulnerabilities.

        Args:
            tools: List of tool definitions or names.

        Yields:
            ToolChainingFinding for each issue.
        """
        # Normalize tool names
        tool_names = set()
        for tool in tools:
            if isinstance(tool, dict):
                name = tool.get("name", "").lower()
            else:
                name = tool.lower()
            tool_names.add(name)

        # Check for dangerous combinations
        for combo1, combo2 in self.DANGEROUS_COMBINATIONS:
            has_combo1 = bool(tool_names & combo1)
            has_combo2 = bool(tool_names & combo2)

            if has_combo1 and has_combo2:
                matched1 = list(tool_names & combo1)
                matched2 = list(tool_names & combo2)

                yield ToolChainingFinding(
                    pattern_name="dangerous_tool_combination",
                    severity=Severity.HIGH,
                    description=f"Dangerous combination: {matched1} + {matched2}",
                    tools_involved=matched1 + matched2,
                    evidence=f"Tools {matched1} combined with {matched2}",
                    remediation="Restrict tool access or add approval workflow",
                )

        # Check for overly broad tool access
        dangerous_tools = {"execute", "exec", "shell", "eval", "run_command", "sql"}
        present_dangerous = tool_names & dangerous_tools

        if len(present_dangerous) > 1:
            yield ToolChainingFinding(
                pattern_name="multiple_dangerous_tools",
                severity=Severity.HIGH,
                description="Multiple dangerous execution tools available",
                tools_involved=list(present_dangerous),
                remediation="Limit dangerous tool access to minimum necessary",
            )

        # Check for lack of segmentation
        if len(tool_names) > 10:
            yield ToolChainingFinding(
                pattern_name="too_many_tools",
                severity=Severity.MEDIUM,
                description=f"Agent has access to {len(tool_names)} tools",
                tools_involved=list(tool_names)[:10],
                remediation="Consider segmenting tools by capability",
            )

    def analyze_interaction(
        self,
        call_sequence: list[tuple[str, str]],
    ) -> Iterator[ToolChainingFinding]:
        """Analyze tool call sequence for chaining attacks.

        Args:
            call_sequence: List of (tool_name, tool_input) tuples.

        Yields:
            ToolChainingFinding for suspicious sequences.
        """
        if len(call_sequence) < 2:
            return

        # Look for escalation patterns
        for i in range(len(call_sequence) - 1):
            current_tool = call_sequence[i][0].lower()
            next_tool = call_sequence[i + 1][0].lower()
            next_input = call_sequence[i + 1][1]

            # Check if output of one tool is used to call another
            read_tools = {"read_file", "file_read", "search", "query"}
            exec_tools = {"execute", "exec", "shell", "eval", "run_command"}

            if current_tool in read_tools and next_tool in exec_tools:
                yield ToolChainingFinding(
                    pattern_name="read_to_execute_chain",
                    severity=Severity.HIGH,
                    description="File/data read followed by execution",
                    tools_involved=[current_tool, next_tool],
                    evidence=f"{current_tool} -> {next_tool}",
                    remediation="Add validation between read and execute operations",
                )

            # Check for data flow from external to sensitive
            if "search" in current_tool or "api" in current_tool:
                if "file_write" in next_tool or "execute" in next_tool:
                    yield ToolChainingFinding(
                        pattern_name="external_to_sensitive_chain",
                        severity=Severity.MEDIUM,
                        description="External data flows to sensitive operation",
                        tools_involved=[current_tool, next_tool],
                        evidence=f"{current_tool} -> {next_tool}",
                        remediation="Validate external data before sensitive operations",
                    )

    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation suggestion for a pattern.

        Args:
            pattern_name: Name of the pattern.

        Returns:
            Remediation suggestion.
        """
        remediations = {
            "unrestricted_tool_access": "Limit tool access to only those necessary",
            "auto_approve_tools": "Require human approval for sensitive tools",
            "recursive_tool_call": "Add recursion limits or disable recursive calls",
            "no_call_limit": "Set reasonable limits on tool call iterations",
            "dangerous_tool_combination": "Separate dangerous tools or add approval",
            "tool_output_not_sanitized": "Enable output sanitization",
            "multiple_dangerous_tools": "Restrict to single execution method",
            "too_many_tools": "Segment tools by capability and risk level",
        }

        return remediations.get(pattern_name, "Review tool configuration")
