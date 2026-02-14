"""MCP Server Interrogator.

Orchestrates security testing of remote MCP servers:
1. Connects to MCP server (stdio/SSE/HTTP)
2. Enumerates available tools
3. Generates adversarial test cases
4. Uses Ollama to craft realistic prompts
5. Executes tests and analyzes responses
6. Reports findings
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from mass.core.types import Severity
from mass.mcp.client import MCPClient, MCPTool, MCPTransport, ToolCallResult
from mass.mcp.tool_tester import (
    MCPToolTester,
    TestCase,
    TestResult,
    AttackCategory,
)
from mass.mcp.response_analyzer import ResponseAnalyzer, Anomaly, AnomalyType
from mass.mcp.prompt_crafter import OllamaPromptCrafter, CraftedPrompt

logger = logging.getLogger(__name__)


class InterrogationStatus(str, Enum):
    """Status of an interrogation job."""
    PENDING = "pending"
    CONNECTING = "connecting"
    ENUMERATING = "enumerating"
    TESTING = "testing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class InterrogationConfig:
    """Configuration for MCP interrogation."""
    # Connection settings
    transport: MCPTransport = MCPTransport.STDIO
    command: str = ""  # For stdio
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""  # For HTTP/SSE
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0

    # Testing settings
    attack_categories: list[AttackCategory] = field(default_factory=lambda: list(AttackCategory))
    max_payloads_per_category: int = 5
    run_benign_baseline: bool = True
    baseline_samples: int = 3

    # Ollama settings
    use_ollama: bool = False
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Execution settings
    parallel_tests: int = 1
    delay_between_tests_ms: int = 100
    stop_on_critical: bool = False


@dataclass
class InterrogationFinding:
    """A security finding from interrogation."""
    id: str = field(default_factory=lambda: str(uuid4()))
    tool_name: str = ""
    parameter_name: str = ""
    attack_category: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    test_case: TestCase | None = None
    anomaly: Anomaly | None = None


@dataclass
class InterrogationResult:
    """Result of an MCP interrogation."""
    id: str = field(default_factory=lambda: str(uuid4()))
    status: InterrogationStatus = InterrogationStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Server info
    server_info: dict[str, Any] = field(default_factory=dict)
    tools_discovered: list[MCPTool] = field(default_factory=list)

    # Test results
    total_tests: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    test_results: list[TestResult] = field(default_factory=list)

    # Findings
    findings: list[InterrogationFinding] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)

    # Crafted prompts (if Ollama used)
    crafted_prompts: list[CraftedPrompt] = field(default_factory=list)

    # Errors
    error: str | None = None

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def has_critical(self) -> bool:
        return self.severity_counts.get("critical", 0) > 0


class MCPInterrogator:
    """Orchestrates security testing of MCP servers."""

    def __init__(self, config: InterrogationConfig):
        self.config = config
        self._client: MCPClient | None = None
        self._tester = MCPToolTester(
            include_categories=config.attack_categories,
            max_payloads_per_category=config.max_payloads_per_category,
        )
        self._analyzer = ResponseAnalyzer()
        self._crafter: OllamaPromptCrafter | None = None
        self._result = InterrogationResult()
        self._cancelled = False

    async def run(self) -> InterrogationResult:
        """Run the full interrogation."""
        self._result.started_at = datetime.utcnow()
        self._result.status = InterrogationStatus.CONNECTING

        try:
            # Connect to MCP server
            await self._connect()

            if self._cancelled:
                self._result.status = InterrogationStatus.CANCELLED
                return self._result

            # Enumerate tools
            self._result.status = InterrogationStatus.ENUMERATING
            await self._enumerate_tools()

            if self._cancelled:
                self._result.status = InterrogationStatus.CANCELLED
                return self._result

            # Run baseline if configured
            if self.config.run_benign_baseline:
                await self._run_baseline()

            # Initialize Ollama crafter if configured
            if self.config.use_ollama:
                self._crafter = OllamaPromptCrafter(
                    base_url=self.config.ollama_url,
                    model=self.config.ollama_model,
                )

            # Generate and run tests
            self._result.status = InterrogationStatus.TESTING
            await self._run_tests()

            # Analyze results
            self._result.status = InterrogationStatus.ANALYZING
            self._analyze_results()

            self._result.status = InterrogationStatus.COMPLETED

        except Exception as e:
            logger.exception("Interrogation failed")
            self._result.status = InterrogationStatus.FAILED
            self._result.error = str(e)

        finally:
            await self._disconnect()
            self._result.completed_at = datetime.utcnow()

        return self._result

    def cancel(self) -> None:
        """Cancel the interrogation."""
        self._cancelled = True

    async def _connect(self) -> None:
        """Connect to the MCP server with transport auto-fallback."""
        transport = self.config.transport
        logger.info(f"Connecting to MCP server via {transport}")

        if transport == MCPTransport.STDIO:
            self._client = MCPClient.stdio(
                command=self.config.command,
                args=self.config.args,
                env=self.config.env,
            )
            await self._client.connect()
        elif transport in (MCPTransport.HTTP, MCPTransport.SSE):
            # Try primary transport, auto-fallback to the other on failure
            primary = transport
            fallback = MCPTransport.HTTP if transport == MCPTransport.SSE else MCPTransport.SSE
            url = self.config.url

            try:
                self._client = self._create_http_client(primary, url)
                await self._client.connect()
                logger.info(f"Connected via {primary.value} transport")
            except Exception as primary_err:
                logger.warning(
                    f"{primary.value} transport failed ({primary_err}), "
                    f"trying {fallback.value} fallback..."
                )
                # Cleanup failed client
                try:
                    await self._client.disconnect()
                except Exception:
                    pass

                # Adjust URL for fallback: /sse ↔ /mcp
                fallback_url = self._adjust_url_for_transport(url, fallback)

                try:
                    self._client = self._create_http_client(fallback, fallback_url)
                    await self._client.connect()
                    logger.info(f"Connected via {fallback.value} fallback transport")
                except Exception as fallback_err:
                    raise RuntimeError(
                        f"Both transports failed for {url}.\n"
                        f"  {primary.value}: {primary_err}\n"
                        f"  {fallback.value} ({fallback_url}): {fallback_err}\n"
                        f"The MCP server may be down or unreachable."
                    )

        self._result.server_info = await self._client.get_server_info()
        logger.info(f"Connected to MCP server: {self._result.server_info}")

    def _create_http_client(self, transport: MCPTransport, url: str) -> MCPClient:
        """Create an MCPClient for the given HTTP-based transport."""
        if transport == MCPTransport.SSE:
            return MCPClient.sse(
                sse_url=url,
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
        else:
            return MCPClient.http(
                base_url=url,
                headers=self.config.headers,
                timeout=self.config.timeout,
            )

    @staticmethod
    def _adjust_url_for_transport(url: str, target: MCPTransport) -> str:
        """Adjust URL path for the target transport (sse ↔ http/mcp)."""
        if target == MCPTransport.SSE:
            if url.endswith("/mcp"):
                return url[:-4] + "/sse"
            if not url.endswith("/sse"):
                return url.rstrip("/") + "/sse"
        else:  # HTTP
            if url.endswith("/sse"):
                return url[:-4] + "/mcp"
            if not url.endswith("/mcp"):
                return url.rstrip("/") + "/mcp"
        return url

    async def _disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self._client:
            try:
                await self._client.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting: {e}")

        if self._crafter:
            try:
                await self._crafter.__aexit__(None, None, None)
            except Exception:
                pass

    async def _enumerate_tools(self) -> None:
        """Enumerate available tools."""
        logger.info("Enumerating tools...")
        tools = await self._client.list_tools()
        self._result.tools_discovered = tools
        logger.info(f"Discovered {len(tools)} tools")

        for tool in tools:
            logger.info(f"  - {tool.name}: {tool.description[:50]}...")
            for param in tool.parameters:
                flags = []
                if param.is_path:
                    flags.append("path")
                if param.is_url:
                    flags.append("url")
                if param.is_command:
                    flags.append("command")
                if param.is_query:
                    flags.append("query")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                logger.debug(f"    - {param.name}: {param.type}{flag_str}")

    async def _run_baseline(self) -> None:
        """Run benign calls to establish baseline behavior."""
        logger.info("Establishing baseline behavior...")

        for tool in self._result.tools_discovered:
            response_times: list[float] = []
            response_sizes: list[int] = []
            response_keys: list[set[str]] = []

            for _ in range(self.config.baseline_samples):
                # Generate benign arguments
                args = self._generate_benign_args(tool)

                result = await self._client.call_tool(tool.name, args)

                response_times.append(result.duration_ms)
                if result.result:
                    response_sizes.append(len(str(result.result)))
                    if isinstance(result.result, dict):
                        response_keys.append(set(result.result.keys()))

                await asyncio.sleep(self.config.delay_between_tests_ms / 1000)

            # Establish baseline
            self._analyzer.establish_baseline(
                tool.name,
                response_times,
                response_sizes,
                response_keys,
            )

            logger.debug(
                f"Baseline for {tool.name}: "
                f"avg_time={sum(response_times)/len(response_times):.0f}ms"
            )

    def _generate_benign_args(self, tool: MCPTool) -> dict[str, Any]:
        """Generate benign arguments for baseline testing."""
        args: dict[str, Any] = {}

        for param in tool.parameters:
            if not param.required and param.default is None:
                continue

            if param.enum:
                args[param.name] = param.enum[0]
            elif param.default is not None:
                args[param.name] = param.default
            elif param.type == "string":
                args[param.name] = "test"
            elif param.type == "integer":
                args[param.name] = 1
            elif param.type == "number":
                args[param.name] = 1.0
            elif param.type == "boolean":
                args[param.name] = True
            elif param.type == "array":
                args[param.name] = []
            elif param.type == "object":
                args[param.name] = {}

        return args

    async def _run_tests(self) -> None:
        """Generate and run security tests."""
        all_tests: list[TestCase] = []

        # Generate test cases for each tool
        for tool in self._result.tools_discovered:
            tests = self._tester.generate_test_cases(tool)
            all_tests.extend(tests)

        self._result.total_tests = len(all_tests)
        logger.info(f"Running {len(all_tests)} security tests...")

        # Run tests
        for i, test_case in enumerate(all_tests):
            if self._cancelled:
                break

            if self.config.stop_on_critical and self._result.has_critical:
                logger.warning("Critical finding detected, stopping tests")
                break

            logger.debug(
                f"Test {i+1}/{len(all_tests)}: "
                f"{test_case.tool_name}.{test_case.parameter_name} "
                f"[{test_case.attack_category.value}]"
            )

            # Optionally craft a realistic prompt
            if self._crafter:
                try:
                    crafted = await self._crafter.craft_attack_prompt(
                        self._get_tool(test_case.tool_name),
                        test_case,
                    )
                    self._result.crafted_prompts.append(crafted)
                except Exception as e:
                    logger.warning(f"Failed to craft prompt: {e}")

            # Execute test
            result = await self._client.call_tool(
                test_case.tool_name,
                test_case.full_arguments,
            )

            # Analyze result
            test_result = self._tester.analyze_result(test_case, result)
            self._result.test_results.append(test_result)

            if test_result.passed:
                self._result.tests_passed += 1
            else:
                self._result.tests_failed += 1

                # Create finding
                for finding_desc in test_result.findings:
                    finding = InterrogationFinding(
                        tool_name=test_case.tool_name,
                        parameter_name=test_case.parameter_name,
                        attack_category=test_case.attack_category.value,
                        severity=test_case.severity,
                        title=f"{test_case.attack_category.value.replace('_', ' ').title()} in {test_case.tool_name}",
                        description=finding_desc,
                        evidence=test_result.evidence,
                        recommendation=self._get_recommendation(test_case.attack_category),
                        test_case=test_case,
                    )
                    self._result.findings.append(finding)

            # Check for response anomalies
            anomalies = self._analyzer.analyze_response(
                tool_name=test_case.tool_name,
                arguments=test_case.full_arguments,
                result=result.result,
                success=result.success,
                error=result.error,
                duration_ms=result.duration_ms,
            )

            for anomaly in anomalies:
                self._result.anomalies.append(anomaly)

                # Convert anomaly to finding if severe
                if anomaly.severity in (Severity.CRITICAL, Severity.HIGH):
                    finding = InterrogationFinding(
                        tool_name=test_case.tool_name,
                        parameter_name=test_case.parameter_name,
                        attack_category=anomaly.anomaly_type.value,
                        severity=anomaly.severity,
                        title=f"{anomaly.anomaly_type.value.replace('_', ' ').title()} Detected",
                        description=anomaly.description,
                        evidence=anomaly.evidence,
                        recommendation=anomaly.recommendation,
                        anomaly=anomaly,
                    )
                    self._result.findings.append(finding)

            # Delay between tests
            await asyncio.sleep(self.config.delay_between_tests_ms / 1000)

    def _get_tool(self, name: str) -> MCPTool | None:
        """Get tool by name."""
        for tool in self._result.tools_discovered:
            if tool.name == name:
                return tool
        return None

    def _get_recommendation(self, category: AttackCategory) -> str:
        """Get remediation recommendation for attack category."""
        recommendations = {
            AttackCategory.COMMAND_INJECTION: (
                "OS Command Injection Remediation: Validate and sanitize all input before "
                "passing to shell commands. Use parameterized execution APIs instead of string "
                "concatenation. Implement allowlists for permitted commands. Avoid shell=True "
                "in subprocess calls and use array-based command execution."
            ),
            AttackCategory.PATH_TRAVERSAL: (
                "Path Traversal (Directory Traversal) Remediation: Validate file paths against "
                "an allowlist of permitted directories. Use canonical path resolution (realpath) "
                "and reject paths containing '..' sequences or that resolve outside the allowed "
                "directory. Implement chroot or container isolation for file operations."
            ),
            AttackCategory.SSRF: (
                "SSRF (Server-Side Request Forgery) Remediation: Validate and allowlist permitted "
                "URLs and domains. Block access to internal IP ranges (10.x, 172.16-31.x, "
                "192.168.x, 169.254.x) and cloud metadata endpoints (169.254.169.254). Use a "
                "proxy service for outbound requests with strict egress filtering."
            ),
            AttackCategory.SQL_INJECTION: (
                "SQL Injection (SQLi) Remediation: Use parameterized queries or prepared "
                "statements exclusively. Never concatenate user input into SQL strings. "
                "Implement input validation, use ORM frameworks, and apply principle of "
                "least privilege for database accounts."
            ),
            AttackCategory.PROMPT_INJECTION: (
                "Prompt Injection Remediation: Clearly separate user input from system "
                "instructions using delimiters or structured formats. Implement input "
                "sanitization to remove instruction-like patterns. Use output validation "
                "to detect instruction leakage or unexpected behavior changes."
            ),
            AttackCategory.TEMPLATE_INJECTION: (
                "SSTI (Server-Side Template Injection) Remediation: Disable dangerous template "
                "features and enable sandbox mode (e.g., Jinja2 SandboxedEnvironment). Never "
                "render user input as template code. Use safe alternatives like string "
                "formatting or pre-compiled templates."
            ),
            AttackCategory.XSS: (
                "XSS (Cross-Site Scripting) Remediation: Encode all user-supplied data before "
                "rendering in HTML context. Use Content-Security-Policy headers. Implement "
                "input validation and use frameworks that auto-escape output by default."
            ),
            AttackCategory.LDAP_INJECTION: (
                "LDAP Injection Remediation: Use parameterized LDAP queries or prepared "
                "statements. Escape special LDAP characters in user input. Validate input "
                "against expected patterns and implement strict access controls."
            ),
            AttackCategory.DENIAL_OF_SERVICE: (
                "DoS (Denial of Service) Remediation: Implement rate limiting and request "
                "throttling. Set appropriate timeouts and resource limits. Use pagination "
                "for large data sets and validate input sizes before processing."
            ),
        }
        return recommendations.get(category, "Review and implement appropriate input validation.")

    def _analyze_results(self) -> None:
        """Perform final analysis and deduplication."""
        # Deduplicate findings
        seen = set()
        unique_findings = []

        for finding in self._result.findings:
            key = (finding.tool_name, finding.attack_category, finding.severity)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        self._result.findings = unique_findings

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        self._result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        logger.info(
            f"Interrogation complete: {self._result.tests_passed} passed, "
            f"{self._result.tests_failed} failed, {len(self._result.findings)} findings"
        )


async def interrogate_mcp_server(
    config: InterrogationConfig,
    progress_callback: callable = None,
) -> InterrogationResult:
    """High-level function to interrogate an MCP server."""
    interrogator = MCPInterrogator(config)
    return await interrogator.run()
