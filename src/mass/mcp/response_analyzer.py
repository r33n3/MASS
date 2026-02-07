"""Response anomaly detector for MCP tool outputs.

Detects oddities in tool behavior:
- Restriction bypass (tool executes when it shouldn't)
- Extra actions (tool does more than expected)
- Information leakage
- Confused deputy attacks
- State manipulation
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import Severity

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Types of anomalies detected in tool responses."""
    RESTRICTION_BYPASS = "restriction_bypass"
    EXTRA_ACTION = "extra_action"
    INFORMATION_LEAKAGE = "information_leakage"
    CONFUSED_DEPUTY = "confused_deputy"
    STATE_MANIPULATION = "state_manipulation"
    TIMING_ANOMALY = "timing_anomaly"
    RESPONSE_SIZE_ANOMALY = "response_size_anomaly"
    ERROR_DISCLOSURE = "error_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class Anomaly:
    """Detected anomaly in tool response."""
    anomaly_type: AnomalyType
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tool_name: str = ""
    recommendation: str = ""


@dataclass
class ToolBaseline:
    """Baseline behavior for a tool."""
    tool_name: str
    avg_response_time_ms: float = 0.0
    avg_response_size: int = 0
    typical_response_keys: set[str] = field(default_factory=set)
    error_patterns: list[str] = field(default_factory=list)
    expected_capabilities: set[str] = field(default_factory=set)
    sample_count: int = 0


class ResponseAnalyzer:
    """Analyzes MCP tool responses for security anomalies."""

    def __init__(self):
        self._baselines: dict[str, ToolBaseline] = {}
        self._state_snapshots: list[dict[str, Any]] = []

    def establish_baseline(
        self,
        tool_name: str,
        response_times: list[float],
        response_sizes: list[int],
        response_keys: list[set[str]],
    ) -> ToolBaseline:
        """Establish baseline behavior for a tool from benign calls."""
        baseline = ToolBaseline(
            tool_name=tool_name,
            avg_response_time_ms=sum(response_times) / len(response_times) if response_times else 0,
            avg_response_size=sum(response_sizes) / len(response_sizes) if response_sizes else 0,
            typical_response_keys=set.union(*response_keys) if response_keys else set(),
            sample_count=len(response_times),
        )
        self._baselines[tool_name] = baseline
        return baseline

    def analyze_response(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        success: bool,
        error: str | None,
        duration_ms: float,
        expected_behavior: str | None = None,
    ) -> list[Anomaly]:
        """Analyze a tool response for anomalies."""
        anomalies: list[Anomaly] = []

        # Get baseline if available
        baseline = self._baselines.get(tool_name)

        # Check timing anomaly
        if baseline and baseline.sample_count >= 3:
            timing_anomaly = self._check_timing_anomaly(
                tool_name, duration_ms, baseline
            )
            if timing_anomaly:
                anomalies.append(timing_anomaly)

        # Check response size
        result_str = str(result) if result else ""
        if baseline and baseline.sample_count >= 3:
            size_anomaly = self._check_size_anomaly(
                tool_name, len(result_str), baseline
            )
            if size_anomaly:
                anomalies.append(size_anomaly)

        # Check for restriction bypass
        bypass_anomaly = self._check_restriction_bypass(
            tool_name, arguments, result, success
        )
        if bypass_anomaly:
            anomalies.append(bypass_anomaly)

        # Check for extra actions
        extra_anomaly = self._check_extra_actions(
            tool_name, arguments, result
        )
        if extra_anomaly:
            anomalies.append(extra_anomaly)

        # Check for information leakage
        leakage_anomalies = self._check_information_leakage(
            tool_name, result
        )
        anomalies.extend(leakage_anomalies)

        # Check for error disclosure
        if error:
            error_anomaly = self._check_error_disclosure(tool_name, error)
            if error_anomaly:
                anomalies.append(error_anomaly)

        # Check for confused deputy
        deputy_anomaly = self._check_confused_deputy(
            tool_name, arguments, result
        )
        if deputy_anomaly:
            anomalies.append(deputy_anomaly)

        # Check for data exfiltration indicators
        exfil_anomaly = self._check_data_exfiltration(
            tool_name, arguments, result
        )
        if exfil_anomaly:
            anomalies.append(exfil_anomaly)

        return anomalies

    def _check_timing_anomaly(
        self,
        tool_name: str,
        duration_ms: float,
        baseline: ToolBaseline,
    ) -> Anomaly | None:
        """Check for unusual response timing."""
        # Check for significantly slower response (could indicate injection)
        if duration_ms > baseline.avg_response_time_ms * 3:
            # If response is 3x slower, might be time-based injection
            if duration_ms > 4000:  # More than 4 seconds
                return Anomaly(
                    anomaly_type=AnomalyType.TIMING_ANOMALY,
                    severity=Severity.HIGH,
                    description=(
                        f"Tool '{tool_name}' responded in {duration_ms:.0f}ms, "
                        f"significantly slower than baseline {baseline.avg_response_time_ms:.0f}ms. "
                        f"This may indicate time-based injection."
                    ),
                    evidence={
                        "duration_ms": duration_ms,
                        "baseline_ms": baseline.avg_response_time_ms,
                        "ratio": duration_ms / baseline.avg_response_time_ms,
                    },
                    tool_name=tool_name,
                    recommendation=(
                        "Time-Based Blind Injection Remediation: This timing anomaly may indicate "
                        "a time-based blind SQL injection or similar vulnerability. Review all "
                        "database queries for proper parameterization. Implement query timeouts "
                        "and monitor for unusual execution times."
                    ),
                )
        return None

    def _check_size_anomaly(
        self,
        tool_name: str,
        response_size: int,
        baseline: ToolBaseline,
    ) -> Anomaly | None:
        """Check for unusual response size."""
        if baseline.avg_response_size == 0:
            return None

        ratio = response_size / baseline.avg_response_size

        # Response significantly larger (could indicate data dump)
        if ratio > 10 and response_size > 10000:
            return Anomaly(
                anomaly_type=AnomalyType.RESPONSE_SIZE_ANOMALY,
                severity=Severity.HIGH,
                description=(
                    f"Tool '{tool_name}' returned {response_size} bytes, "
                    f"{ratio:.1f}x larger than baseline. May indicate data exfiltration."
                ),
                evidence={
                    "response_size": response_size,
                    "baseline_size": baseline.avg_response_size,
                    "ratio": ratio,
                },
                tool_name=tool_name,
                recommendation=(
                    "Response Size Anomaly Remediation: Unusually large responses may indicate "
                    "SQL Injection (SQLi) data exfiltration or unintended data exposure. Review "
                    "query result limiting, implement pagination, and ensure proper access "
                    "controls to prevent unauthorized bulk data retrieval."
                ),
            )

        return None

    def _check_restriction_bypass(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        success: bool,
    ) -> Anomaly | None:
        """Check if tool executed when it should have been restricted."""
        result_str = str(result).lower() if result else ""

        # Check for signs of restriction bypass
        bypass_indicators = [
            # Command execution evidence
            ("uid=", "Command execution detected"),
            ("gid=", "Command execution detected"),
            ("root:", "Privileged access detected"),
            # File access evidence
            ("/etc/passwd", "System file access"),
            ("C:\\Windows\\System32", "Windows system access"),
            # Database evidence
            ("information_schema", "Database schema exposure"),
            ("mysql.user", "Database credential exposure"),
            # Cloud metadata
            ("ami-", "AWS metadata access"),
            ("instance-id", "Cloud instance metadata"),
            ("169.254.169.254", "Metadata endpoint access"),
        ]

        for indicator, desc in bypass_indicators:
            if indicator.lower() in result_str:
                return Anomaly(
                    anomaly_type=AnomalyType.RESTRICTION_BYPASS,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Tool '{tool_name}' appears to have bypassed restrictions. "
                        f"{desc}."
                    ),
                    evidence={
                        "indicator": indicator,
                        "arguments": arguments,
                        "result_sample": result_str[:500],
                    },
                    tool_name=tool_name,
                    recommendation=(
                        "Restriction Bypass Remediation: The tool appears to have bypassed "
                        "security restrictions. Implement strict input validation using allowlists. "
                        "For file operations, use chroot isolation. For network requests, block "
                        "internal IP ranges and metadata endpoints. Sanitize all output to prevent "
                        "sensitive data exposure."
                    ),
                )

        return None

    def _check_extra_actions(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> Anomaly | None:
        """Check if tool performed more actions than expected."""
        result_str = str(result).lower() if result else ""

        # Signs of extra actions
        extra_action_patterns = [
            (r"(created|wrote|saved)\s+(file|directory)", "Unexpected file creation"),
            (r"(deleted|removed)\s+(file|record)", "Unexpected deletion"),
            (r"(sent|posted|emailed)\s+to", "Unexpected network activity"),
            (r"(modified|updated|changed)\s+(config|setting)", "Unexpected configuration change"),
            (r"(executed|ran|started)\s+(command|process|script)", "Unexpected execution"),
            (r"(connected|logged)\s+(to|into)", "Unexpected connection"),
        ]

        for pattern, desc in extra_action_patterns:
            if re.search(pattern, result_str):
                return Anomaly(
                    anomaly_type=AnomalyType.EXTRA_ACTION,
                    severity=Severity.HIGH,
                    description=(
                        f"Tool '{tool_name}' may have performed unexpected actions. "
                        f"{desc} detected in response."
                    ),
                    evidence={
                        "pattern": pattern,
                        "arguments": arguments,
                        "result_sample": result_str[:500],
                    },
                    tool_name=tool_name,
                    recommendation=(
                        "Extra Action Remediation: The tool performed actions beyond its expected "
                        "scope. This may indicate Confused Deputy or Privilege Escalation issues. "
                        "Review tool permissions and implement the principle of least privilege. "
                        "Add explicit action validation and audit logging for all operations."
                    ),
                )

        return None

    def _check_information_leakage(
        self,
        tool_name: str,
        result: Any,
    ) -> list[Anomaly]:
        """Check for sensitive information leakage."""
        anomalies: list[Anomaly] = []
        result_str = str(result) if result else ""

        # Check for various types of leakage
        leakage_checks = [
            # API keys and tokens
            (r'(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
             "API key exposure", Severity.CRITICAL),
            (r'(bearer|token)["\s:=]+["\']?([a-zA-Z0-9_.-]{20,})',
             "Authentication token exposure", Severity.CRITICAL),
            (r'(sk-|pk_|rk_)[a-zA-Z0-9]{20,}',
             "Service key exposure", Severity.CRITICAL),

            # Credentials
            (r'(password|passwd|pwd)["\s:=]+["\']?([^\s"\']+)',
             "Password exposure", Severity.CRITICAL),
            (r'(secret|private[_-]?key)["\s:=]+["\']?([^\s"\']+)',
             "Secret exposure", Severity.CRITICAL),

            # Connection strings
            (r'(mongodb|postgres|mysql|redis)://[^\s]+',
             "Database connection string", Severity.HIGH),
            (r'(jdbc|odbc):[^\s]+',
             "Database connection string", Severity.HIGH),

            # Internal paths and IPs
            (r'(/home/[a-z_][a-z0-9_-]*/|/var/[a-z]+/|/opt/[a-z]+/)',
             "Internal path disclosure", Severity.MEDIUM),
            (r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
             "Internal IP disclosure", Severity.MEDIUM),

            # AWS/Cloud specifics
            (r'AKIA[0-9A-Z]{16}',
             "AWS Access Key ID", Severity.CRITICAL),
            (r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-z0-9-/]+',
             "AWS ARN disclosure", Severity.MEDIUM),

            # Stack traces
            (r'(Traceback \(most recent|at .+\(.+:\d+\)|Exception in)',
             "Stack trace disclosure", Severity.LOW),
        ]

        for pattern, desc, severity in leakage_checks:
            if re.search(pattern, result_str, re.IGNORECASE):
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.INFORMATION_LEAKAGE,
                    severity=severity,
                    description=f"Tool '{tool_name}' may have leaked sensitive data: {desc}",
                    evidence={
                        "pattern": pattern,
                        "result_sample": result_str[:500],
                    },
                    tool_name=tool_name,
                    recommendation=(
                        "Information Leakage Remediation: Sensitive data (PII, credentials, API keys) "
                        "detected in tool output. Implement data masking and redaction for sensitive "
                        "fields. Use tokenization for credentials. Apply output filters to detect "
                        "and block patterns matching credit cards, SSNs, API keys, and passwords."
                    ),
                ))

        return anomalies

    def _check_error_disclosure(
        self,
        tool_name: str,
        error: str,
    ) -> Anomaly | None:
        """Check if error message reveals sensitive information."""
        error_lower = error.lower()

        # Check for verbose error details
        sensitive_patterns = [
            ("sql", "SQL error reveals database details"),
            ("syntax error", "Syntax error may reveal query structure"),
            ("connection refused", "Network topology disclosure"),
            ("file not found", "Path enumeration possible"),
            ("permission denied", "Access control information"),
            ("stack trace", "Implementation details in error"),
            ("at line", "Source code location disclosure"),
            ("/home/", "Server path disclosure"),
            ("/var/", "Server configuration disclosure"),
        ]

        for pattern, desc in sensitive_patterns:
            if pattern in error_lower:
                # Only flag if error is verbose
                if len(error) > 200:
                    return Anomaly(
                        anomaly_type=AnomalyType.ERROR_DISCLOSURE,
                        severity=Severity.MEDIUM,
                        description=f"Tool '{tool_name}' error reveals sensitive details: {desc}",
                        evidence={
                            "error_sample": error[:500],
                        },
                        tool_name=tool_name,
                        recommendation=(
                            "Error Disclosure Remediation: Detailed error messages expose internal "
                            "system information. Implement generic user-facing error messages while "
                            "logging detailed errors server-side. Never expose stack traces, file "
                            "paths, database schemas, or version information to end users."
                        ),
                    )

        return None

    def _check_confused_deputy(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> Anomaly | None:
        """Check for confused deputy attack indicators."""
        result_str = str(result).lower() if result else ""
        args_str = str(arguments).lower()

        # Check if tool acted on behalf of different principal
        deputy_indicators = [
            # Acting as different user
            ("as user", "Tool may have acted as different user"),
            ("on behalf of", "Tool acted on behalf of attacker"),
            ("impersonating", "Impersonation detected"),
            # Cross-tenant access
            ("tenant_id", "Possible cross-tenant access"),
            ("organization_id", "Cross-organization access"),
            # Privilege mixing
            ("admin", "Administrative action"),
            ("root", "Root-level action"),
            ("sudo", "Elevated privileges"),
        ]

        # Only flag if the argument contained injection-like patterns
        if any(c in args_str for c in [";", "|", "$", "`", "{{"]):
            for indicator, desc in deputy_indicators:
                if indicator in result_str:
                    return Anomaly(
                        anomaly_type=AnomalyType.CONFUSED_DEPUTY,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Tool '{tool_name}' may be vulnerable to confused deputy attack. "
                            f"{desc}."
                        ),
                        evidence={
                            "arguments": arguments,
                            "indicator": indicator,
                        },
                        tool_name=tool_name,
                        recommendation=(
                            "Confused Deputy Remediation: The tool may have accessed resources using "
                            "the system's credentials rather than the user's. Implement proper "
                            "authorization checks at every access point. Validate that requested "
                            "resources match the user's permissions. Use separate service accounts "
                            "with minimal privileges for different operations."
                        ),
                    )

        return None

    def _check_data_exfiltration(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> Anomaly | None:
        """Check for data exfiltration indicators."""
        result_str = str(result).lower() if result else ""
        args_str = str(arguments).lower()

        # Check for external data transfer
        exfil_indicators = [
            (r'https?://[^\s]+\.(burp|oast|interact|webhook)', "Data sent to attacker endpoint"),
            (r'dns query.*\.[a-z]+\.[a-z]+', "DNS-based exfiltration"),
            (r'(uploaded|sent|posted|transferred)\s+\d+\s+(bytes|kb|mb)', "Data transfer detected"),
            (r'base64["\s:]+[a-zA-Z0-9+/=]{50,}', "Base64 encoded data transfer"),
        ]

        for pattern, desc in exfil_indicators:
            if re.search(pattern, result_str, re.IGNORECASE):
                return Anomaly(
                    anomaly_type=AnomalyType.DATA_EXFILTRATION,
                    severity=Severity.CRITICAL,
                    description=f"Tool '{tool_name}' may have exfiltrated data: {desc}",
                    evidence={
                        "pattern": pattern,
                        "arguments": arguments,
                        "result_sample": result_str[:500],
                    },
                    tool_name=tool_name,
                    recommendation=(
                        "Data Exfiltration Remediation: Evidence of data being sent to external "
                        "destinations or encoded for transmission. Implement egress filtering with "
                        "allowlisted destinations. Monitor for unusual encoding patterns (Base64, "
                        "hex encoding) in outputs. Add DLP (Data Loss Prevention) controls to "
                        "detect and block sensitive data leaving the system."
                    ),
                )

        return None

    def track_state(self, state_snapshot: dict[str, Any]) -> None:
        """Track state changes between tool calls."""
        self._state_snapshots.append(state_snapshot)

    def detect_state_anomalies(self) -> list[Anomaly]:
        """Detect anomalies in state changes over time."""
        anomalies: list[Anomaly] = []

        if len(self._state_snapshots) < 2:
            return anomalies

        prev = self._state_snapshots[-2]
        curr = self._state_snapshots[-1]

        # Check for unexpected state changes
        prev_keys = set(prev.keys())
        curr_keys = set(curr.keys())

        # New unexpected keys
        new_keys = curr_keys - prev_keys
        if new_keys:
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.STATE_MANIPULATION,
                severity=Severity.MEDIUM,
                description=f"Unexpected new state keys appeared: {new_keys}",
                evidence={
                    "new_keys": list(new_keys),
                    "prev_snapshot": prev,
                    "curr_snapshot": curr,
                },
                recommendation=(
                    "State Manipulation Remediation: Tool state may have been manipulated through "
                    "input. Review all state management for injection vulnerabilities. Implement "
                    "immutable state patterns where possible. Validate state transitions and use "
                    "cryptographic signatures to detect unauthorized modifications."
                ),
            ))

        # Deleted keys
        deleted_keys = prev_keys - curr_keys
        if deleted_keys:
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.STATE_MANIPULATION,
                severity=Severity.MEDIUM,
                description=f"State keys unexpectedly removed: {deleted_keys}",
                evidence={
                    "deleted_keys": list(deleted_keys),
                },
                recommendation=(
                    "State Persistence Remediation: State changes that persist between calls may "
                    "indicate a state pollution or session fixation vulnerability. Implement proper "
                    "session isolation. Use unique identifiers for each session. Clear state "
                    "between operations and implement access controls for persisted data."
                ),
            ))

        return anomalies
