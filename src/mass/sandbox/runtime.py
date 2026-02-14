"""Runtime simulation engine for sandbox testing.

The SandboxRuntime is a mini-orchestrator that simulates an AI application's
internal flow: prompt assembly -> model call -> tool interception -> memory
tracking -> assertion checking -> detector scoring.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from mass.core.findings import Evidence, Finding
from mass.core.types import AttackCategory, ComponentType, Severity
from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, ToolCall

from mass.sandbox.logger import SandboxLogger
from mass.sandbox.scenario import Assertion, MemoryOp, Scenario, ScenarioTurn, ToolMock

logger = logging.getLogger("mass.sandbox.runtime")

# Map severity strings to enum
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Map scenario category to AttackCategory
_CATEGORY_MAP = {
    "boundary": AttackCategory.SYSTEM_PROMPT_LEAKAGE,
    "tool": AttackCategory.EXCESSIVE_AGENCY,
    "routing": AttackCategory.PROMPT_INJECTION,
    "memory": AttackCategory.DATA_LEAKAGE,
    "load": AttackCategory.UNBOUNDED_CONSUMPTION,
    "general": AttackCategory.PROMPT_INJECTION,
}


@dataclass
class StepState:
    """Snapshot of runtime state at one turn."""

    turn_number: int
    user_input: str
    assembled_prompt: list[dict[str, Any]] = field(default_factory=list)
    model_response: str = ""
    tool_calls_made: list[ToolCall] = field(default_factory=list)
    tool_responses: list[dict[str, Any]] = field(default_factory=list)
    memory_before: dict[str, Any] = field(default_factory=dict)
    memory_after: dict[str, Any] = field(default_factory=dict)
    memory_diff: dict[str, Any] = field(default_factory=dict)
    routing_decision: str | None = None
    latency_ms: float = 0.0
    tokens_used: int = 0
    assertions_passed: list[str] = field(default_factory=list)
    assertions_failed: list[str] = field(default_factory=list)
    detector_results: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_number": self.turn_number,
            "user_input": self.user_input,
            "assembled_prompt": self.assembled_prompt,
            "model_response": self.model_response,
            "tool_calls": [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                for tc in self.tool_calls_made
            ],
            "tool_responses": self.tool_responses,
            "memory_before": self.memory_before,
            "memory_after": self.memory_after,
            "memory_diff": self.memory_diff,
            "routing_decision": self.routing_decision,
            "latency_ms": self.latency_ms,
            "tokens_used": self.tokens_used,
            "assertions_passed": self.assertions_passed,
            "assertions_failed": self.assertions_failed,
            "detector_results": self.detector_results,
            "error": self.error,
        }


@dataclass
class SandboxResult:
    """Complete result of a sandbox run."""

    scenario_name: str
    job_id: str
    status: str = "pending"  # pending | running | completed | failed | error
    steps: list[StepState] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_turns: int = 0
    passed_assertions: int = 0
    failed_assertions: int = 0
    duration_seconds: float = 0.0
    model_used: str = ""
    provider_used: str = ""
    seed: int | None = None
    deployment_id: str | None = None
    validated_finding_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "job_id": self.job_id,
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "total_turns": self.total_turns,
            "passed_assertions": self.passed_assertions,
            "failed_assertions": self.failed_assertions,
            "duration_seconds": self.duration_seconds,
            "model_used": self.model_used,
            "provider_used": self.provider_used,
            "seed": self.seed,
            "deployment_id": self.deployment_id,
            "validated_finding_ids": self.validated_finding_ids,
            "metadata": self.metadata,
        }


class SandboxRuntime:
    """Simulates an AI application runtime for security testing.

    Executes scenario turns through: prompt assembly -> model call ->
    tool interception -> memory tracking -> assertion checking.
    """

    MAX_TOOL_LOOPS = 3  # Max tool-call round-trips per turn

    def __init__(
        self,
        scenario: Scenario,
        runner: BaseRunner,
        sandbox_logger: SandboxLogger | None = None,
        turn_callback: Callable[..., Any] | None = None,
    ) -> None:
        self.scenario = scenario
        self.runner = runner
        self.turn_callback = turn_callback
        self.logger = sandbox_logger or SandboxLogger(
            job_id="", scenario_name=scenario.name,
        )
        self.memory: dict[str, Any] = dict(scenario.initial_memory)
        self.conversation_history: list[dict[str, str]] = []
        self.steps: list[StepState] = []
        self._detectors: list[Any] = []
        self._mcp_client: Any | None = None  # MCPClient for live mode
        self._load_detectors()

    def _load_detectors(self) -> None:
        """Load configured detectors from the registry."""
        try:
            from mass.detectors.base import get_detector

            for name in self.scenario.detectors:
                detector = get_detector(name)
                if detector:
                    self._detectors.append(detector)
                else:
                    logger.warning("Detector not found: %s", name)
        except ImportError:
            logger.warning("Could not import detector registry")

    async def execute(self) -> SandboxResult:
        """Run all scenario turns through the simulated runtime."""
        start_time = time.time()
        job_id = self.logger.telemetry.job_id

        result = SandboxResult(
            scenario_name=self.scenario.name,
            job_id=job_id,
            status="running",
            total_turns=len(self.scenario.turns),
            model_used=self.runner.model,
            provider_used=self.runner.provider,
            seed=self.scenario.seed,
            deployment_id=self.scenario.deployment_id,
            validated_finding_ids=list(self.scenario.validates_findings),
        )

        try:
            # Connect MCP client for live/hybrid mode
            if self.scenario.tool_mode in ("live", "hybrid"):
                await self._connect_mcp()

            for i, turn in enumerate(self.scenario.turns):
                step = await self._execute_turn(i, turn)
                self.steps.append(step)
                result.steps.append(step)
                result.passed_assertions += len(step.assertions_passed)
                result.failed_assertions += len(step.assertions_failed)

                # Broadcast progress
                if self.turn_callback:
                    try:
                        cb_result = self.turn_callback(
                            job_id=job_id,
                            turn_number=i,
                            user_input=step.user_input[:100],
                            model_response=step.model_response[:200],
                            tool_calls=[tc.name for tc in step.tool_calls_made],
                            assertions_passed=len(step.assertions_passed),
                            assertions_failed=len(step.assertions_failed),
                            memory_keys_changed=list(step.memory_diff.keys()),
                        )
                        if asyncio.iscoroutine(cb_result):
                            await cb_result
                    except Exception as e:
                        logger.warning("Turn callback error: %s", e)

            result.status = "completed"

        except Exception as e:
            logger.error("Sandbox execution error: %s", e)
            result.status = "error"
            result.metadata["error"] = str(e)
        finally:
            # Disconnect MCP client
            if self._mcp_client:
                try:
                    await self._mcp_client.disconnect()
                except Exception:
                    pass
                self._mcp_client = None

        result.duration_seconds = time.time() - start_time

        # Generate findings from failed assertions and detector results
        result.findings = self._generate_findings(result)

        return result

    async def _execute_turn(self, turn_idx: int, turn: ScenarioTurn) -> StepState:
        """Execute a single scenario turn."""
        step = StepState(
            turn_number=turn_idx,
            user_input=turn.user_input,
        )

        # 1. Snapshot memory before
        step.memory_before = copy.deepcopy(self.memory)
        self.logger.log_turn_start(turn_idx, turn.user_input, self.memory)

        # 2. Apply pre-turn memory operations
        self._apply_memory_ops(turn.memory_ops, turn_idx)

        # 3. Assemble prompt
        messages = self._assemble_prompt(turn.user_input)
        step.assembled_prompt = copy.deepcopy(messages)
        self.logger.log_prompt_assembled(turn_idx, len(messages), self._estimate_tokens(messages))

        # 4. Call model (with tool-call loop)
        all_tool_calls: list[ToolCall] = []
        all_tool_responses: list[dict[str, Any]] = []
        final_response = ""
        total_latency = 0.0
        total_tokens = 0

        for loop_iter in range(self.MAX_TOOL_LOOPS + 1):
            kwargs: dict[str, Any] = {
                "messages": messages,
                "temperature": self.scenario.temperature,
            }
            if self.scenario.tools:
                kwargs["tools"] = self.scenario.tools
            if self.scenario.seed is not None:
                kwargs["seed"] = self.scenario.seed

            # Run model
            runner_result = await self._run_model(kwargs)

            total_latency += runner_result.latency_ms
            total_tokens += runner_result.tokens_used

            self.logger.log_model_called(
                turn_idx,
                provider=self.runner.provider,
                model=self.runner.model,
                latency_ms=runner_result.latency_ms,
                tokens=runner_result.tokens_used,
                temperature=self.scenario.temperature,
            )

            if not runner_result.is_success:
                step.error = runner_result.error or "Model call failed"
                final_response = runner_result.response or ""
                break

            # Check for tool calls
            if runner_result.tool_calls:
                for tc in runner_result.tool_calls:
                    all_tool_calls.append(tc)
                    self.logger.log_tool_requested(turn_idx, tc.name, tc.arguments)

                # Resolve tool calls via mock or live layer
                tool_responses = await self._resolve_tool_calls(
                    runner_result.tool_calls, turn,
                )
                all_tool_responses.extend(tool_responses)

                # Add assistant message with tool calls to history
                messages.append({
                    "role": "assistant",
                    "content": runner_result.response or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in runner_result.tool_calls
                    ],
                })

                # Add tool response messages
                for tc, resp in zip(runner_result.tool_calls, tool_responses):
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(resp.get("result", resp)),
                    })

                # Continue loop for model to process tool results
                if loop_iter < self.MAX_TOOL_LOOPS:
                    continue

            # No tool calls or max loops reached — capture final response
            final_response = runner_result.response or ""
            break

        step.model_response = final_response
        step.tool_calls_made = all_tool_calls
        step.tool_responses = all_tool_responses
        step.latency_ms = total_latency
        step.tokens_used = total_tokens

        # 5. Update conversation history
        self.conversation_history.append({"role": "user", "content": turn.user_input})
        self.conversation_history.append({"role": "assistant", "content": final_response})

        # 6. Snapshot memory after and compute diff
        step.memory_after = copy.deepcopy(self.memory)
        step.memory_diff = self._compute_memory_diff(step.memory_before, step.memory_after)

        # 7. Run assertions
        passed, failed = self._run_assertions(turn, step)
        step.assertions_passed = passed
        step.assertions_failed = failed

        # 8. Run detectors
        step.detector_results = self._run_detectors(turn.user_input, final_response, turn_idx)

        self.logger.log_turn_complete(turn_idx, final_response, total_tokens)

        return step

    async def _run_model(self, kwargs: dict[str, Any]) -> RunnerResult:
        """Call the model via runner, handling sync/async."""
        try:
            if self.runner.supports_async:
                return await self.runner.run_async("", **kwargs)
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, lambda: self.runner.run("", **kwargs),
                )
        except Exception as e:
            logger.error("Runner error: %s", e)
            return RunnerResult(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=0,
                model=self.runner.model,
                provider=self.runner.provider,
                error=str(e),
            )

    def _assemble_prompt(self, user_input: str) -> list[dict[str, str]]:
        """Build the full message array."""
        messages: list[dict[str, str]] = []

        if self.scenario.system_prompt:
            messages.append({"role": "system", "content": self.scenario.system_prompt})

        # Add conversation history
        for msg in self.conversation_history:
            messages.append(msg)

        # Add current user input
        messages.append({"role": "user", "content": user_input})

        return messages

    async def _resolve_tool_calls(
        self,
        tool_calls: list[ToolCall],
        turn: ScenarioTurn,
    ) -> list[dict[str, Any]]:
        """Match tool calls to mocks or live MCP, return responses."""
        mock_map: dict[str, ToolMock] = {
            tm.tool_name: tm for tm in turn.tool_mocks
        }
        responses = []

        for tc in tool_calls:
            # Check if this tool should be called live
            if self._should_use_live(tc.name):
                resp = await self._call_live_tool(tc)
                responses.append(resp)
                continue

            mock = mock_map.get(tc.name)

            if mock is None:
                # No mock defined — return generic success
                resp = {"result": f"Tool '{tc.name}' executed successfully", "status": "ok"}
                self.logger.log_tool_resolved(turn.turn_number if hasattr(turn, 'turn_number') else 0, tc.name, "unmocked", resp)
                responses.append(resp)
                continue

            if mock.mode == "error":
                resp = {
                    "error": mock.error_message or f"Tool '{tc.name}' failed",
                    "status": "error",
                }
            elif mock.mode == "timeout":
                resp = {
                    "error": f"Tool '{tc.name}' timed out after {mock.delay_ms}ms",
                    "status": "timeout",
                }
            elif mock.mode == "malformed":
                resp = {"garbled": True, "data": "<<<MALFORMED>>>"}
            elif mock.mode == "adversarial":
                # Return the configured response but flag it
                if isinstance(mock.response, dict):
                    resp = dict(mock.response)
                    resp["_adversarial"] = True
                else:
                    resp = {"result": mock.response, "_adversarial": True}
            else:
                if isinstance(mock.response, dict):
                    resp = dict(mock.response)
                else:
                    resp = {"result": mock.response}

            self.logger.log_tool_resolved(
                self.steps[-1].turn_number if self.steps else 0,
                tc.name, mock.mode, resp,
            )
            responses.append(resp)

        return responses

    def _should_use_live(self, tool_name: str) -> bool:
        """Check if a tool should be called live via MCP."""
        if self._mcp_client is None:
            return False
        if self.scenario.tool_mode == "live":
            return True
        if self.scenario.tool_mode == "hybrid":
            return tool_name in self.scenario.live_tools
        return False

    async def _call_live_tool(self, tc: ToolCall) -> dict[str, Any]:
        """Call a tool live via MCP client."""
        turn_num = self.steps[-1].turn_number if self.steps else 0
        try:
            result = await self._mcp_client.call_tool(tc.name, tc.arguments)
            resp: dict[str, Any]
            if result.success:
                resp = {"result": result.result, "_live": True, "_duration_ms": result.duration_ms}
            else:
                resp = {"error": result.error, "_live": True, "_duration_ms": result.duration_ms}
            self.logger.log_tool_resolved(turn_num, tc.name, "live", resp)
            return resp
        except Exception as e:
            logger.warning("Live MCP tool call failed for %s: %s", tc.name, e)
            resp = {"error": f"Live tool call failed: {e}", "_live": True}
            self.logger.log_tool_resolved(turn_num, tc.name, "live_error", resp)
            return resp

    async def _connect_mcp(self) -> None:
        """Connect to MCP server for live tool execution."""
        try:
            from mass.mcp.client import MCPClient

            transport = self.scenario.mcp_transport or "http"
            if transport == "stdio":
                self._mcp_client = MCPClient.stdio(
                    command=self.scenario.mcp_command or "",
                    args=self.scenario.mcp_args,
                    env=self.scenario.mcp_env or None,
                )
            elif transport == "sse":
                self._mcp_client = MCPClient.sse(
                    sse_url=self.scenario.mcp_url or "",
                    headers=self.scenario.mcp_headers or None,
                )
            else:  # http
                self._mcp_client = MCPClient.http(
                    base_url=self.scenario.mcp_url or "",
                    headers=self.scenario.mcp_headers or None,
                )

            await self._mcp_client.connect()

            # Discover tools if not already defined in scenario
            if not self.scenario.tools:
                tools = await self._mcp_client.list_tools()
                self.scenario.tools = [
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema or {"type": "object", "properties": {}},
                        },
                    }
                    for t in tools
                ]
                logger.info("Discovered %d tools from MCP server", len(tools))

        except ImportError:
            logger.error("MCPClient not available — cannot use live tool mode")
            raise RuntimeError("MCPClient not available for live tool execution")
        except Exception as e:
            logger.error("Failed to connect to MCP server: %s", e)
            raise RuntimeError(f"MCP connection failed: {e}")

    def _apply_memory_ops(self, ops: list[MemoryOp], turn_idx: int) -> None:
        """Apply pre-turn memory mutations."""
        for op in ops:
            old_value = self.memory.get(op.key)
            if op.action == "set":
                self.memory[op.key] = op.value
                self.logger.log_memory_write(turn_idx, op.key, old_value, op.value)
            elif op.action == "delete":
                if op.key in self.memory:
                    del self.memory[op.key]
                    self.logger.log_memory_write(turn_idx, op.key, old_value, None)

    def _compute_memory_diff(
        self, before: dict[str, Any], after: dict[str, Any],
    ) -> dict[str, Any]:
        """Compute added/changed/removed keys between snapshots."""
        diff: dict[str, Any] = {"added": {}, "changed": {}, "removed": {}}
        all_keys = set(before.keys()) | set(after.keys())

        for key in all_keys:
            if key not in before:
                diff["added"][key] = after[key]
            elif key not in after:
                diff["removed"][key] = before[key]
            elif before[key] != after[key]:
                diff["changed"][key] = {"before": before[key], "after": after[key]}

        return diff

    def _run_assertions(
        self, turn: ScenarioTurn, step: StepState,
    ) -> tuple[list[str], list[str]]:
        """Evaluate post-turn assertions."""
        passed: list[str] = []
        failed: list[str] = []

        for assertion in turn.assertions:
            label = f"{assertion.type}:{assertion.target}"
            result = self._check_assertion(assertion, step)

            if result:
                passed.append(label)
            else:
                failed.append(label)

            self.logger.log_assertion_check(
                step.turn_number,
                assertion.type,
                assertion.target,
                result,
                expected=assertion.value,
                actual=self._get_assertion_actual(assertion, step),
            )

        return passed, failed

    def _check_assertion(self, assertion: Assertion, step: StepState) -> bool:
        """Check a single assertion against the step state."""
        response_lower = step.model_response.lower()
        target_lower = assertion.target.lower()
        tool_names = [tc.name for tc in step.tool_calls_made]

        if assertion.type == "contains":
            return target_lower in response_lower

        elif assertion.type == "not_contains":
            return target_lower not in response_lower

        elif assertion.type == "tool_called":
            return assertion.target in tool_names

        elif assertion.type == "tool_not_called":
            return assertion.target not in tool_names

        elif assertion.type == "memory_has":
            return assertion.target in step.memory_after

        elif assertion.type == "memory_missing":
            return assertion.target not in step.memory_after

        elif assertion.type == "regex":
            try:
                return bool(re.search(assertion.target, step.model_response, re.IGNORECASE))
            except re.error:
                return False

        elif assertion.type == "response_length":
            try:
                max_len = int(assertion.target)
                return len(step.model_response) <= max_len
            except (ValueError, TypeError):
                return False

        elif assertion.type == "detector":
            # Check if the named detector flagged this as vulnerable
            for dr in step.detector_results:
                if dr.get("detector_name") == assertion.target:
                    # For detector assertions, "pass" means the detector
                    # did NOT find a vulnerability (safe behavior)
                    return dr.get("status") != "vulnerable"
            return True  # Detector not run = pass by default

        return False

    def _get_assertion_actual(self, assertion: Assertion, step: StepState) -> str | None:
        """Get the actual value for assertion logging."""
        if assertion.type in ("contains", "not_contains", "regex"):
            return step.model_response[:200]
        elif assertion.type in ("tool_called", "tool_not_called"):
            return ",".join(tc.name for tc in step.tool_calls_made)
        elif assertion.type in ("memory_has", "memory_missing"):
            return ",".join(step.memory_after.keys())
        return None

    def _run_detectors(
        self, user_input: str, response: str, turn_idx: int,
    ) -> list[dict[str, Any]]:
        """Run configured detectors on the turn's input/output."""
        results = []
        for detector in self._detectors:
            try:
                detection = detector.detect(user_input, response)
                result_dict = {
                    "detector_name": detector.name,
                    "status": detection.status.value if hasattr(detection.status, "value") else str(detection.status),
                    "confidence": detection.confidence,
                    "evidence": detection.evidence if hasattr(detection, "evidence") else [],
                    "details": detection.details if hasattr(detection, "details") else {},
                }
                results.append(result_dict)

                self.logger.log_detector_run(
                    turn_idx,
                    detector.name,
                    result_dict["status"],
                    detection.confidence,
                    result_dict["evidence"],
                )
            except Exception as e:
                logger.warning("Detector %s error: %s", detector.name, e)
                results.append({
                    "detector_name": detector.name,
                    "status": "error",
                    "confidence": 0.0,
                    "evidence": [],
                    "details": {"error": str(e)},
                })

        return results

    def _generate_findings(self, result: SandboxResult) -> list[Finding]:
        """Generate Finding objects from failed assertions and detector hits."""
        findings: list[Finding] = []
        base_severity = _SEVERITY_MAP.get(
            self.scenario.severity_if_fail, Severity.MEDIUM,
        )
        base_category = _CATEGORY_MAP.get(
            self.scenario.category, AttackCategory.PROMPT_INJECTION,
        )

        # Findings from failed assertions
        for step in result.steps:
            for failed_assertion in step.assertions_failed:
                parts = failed_assertion.split(":", 1)
                assertion_type = parts[0]
                assertion_target = parts[1] if len(parts) > 1 else ""

                evidence = Evidence(
                    type="response",
                    content=f"Turn {step.turn_number}: User input: {step.user_input[:200]}\n"
                            f"Model response: {step.model_response[:500]}\n"
                            f"Failed assertion: {failed_assertion}",
                    metadata={
                        "turn_number": step.turn_number,
                        "assertion_type": assertion_type,
                        "assertion_target": assertion_target,
                        "tool_calls": [tc.name for tc in step.tool_calls_made],
                        "sandbox_job_id": result.job_id,
                    },
                )

                finding = Finding(
                    title=f"Sandbox: {assertion_type} assertion failed — {assertion_target}",
                    description=(
                        f"During sandbox scenario '{self.scenario.name}', "
                        f"turn {step.turn_number} failed the '{assertion_type}' assertion "
                        f"for target '{assertion_target}'. "
                        f"User input: \"{step.user_input[:100]}...\""
                    ),
                    severity=base_severity,
                    category=base_category,
                    component_type=ComponentType.MODEL,
                    component_name=self.runner.model,
                    evidence=[evidence],
                    confidence=0.9,
                    tags=["sandbox", self.scenario.category, assertion_type],
                    metadata={
                        "sandbox_scenario": self.scenario.name,
                        "sandbox_job_id": result.job_id,
                        "turn_number": step.turn_number,
                        "assertion": failed_assertion,
                    },
                    scan_id=result.metadata.get("scan_id"),
                    deployment_id=result.deployment_id,
                )
                findings.append(finding)

        # Findings from detector hits
        for step in result.steps:
            for dr in step.detector_results:
                if dr.get("status") == "vulnerable":
                    evidence = Evidence(
                        type="response",
                        content=f"Turn {step.turn_number}: Detector '{dr['detector_name']}' "
                                f"flagged vulnerability (confidence: {dr['confidence']:.2f})\n"
                                f"User input: {step.user_input[:200]}\n"
                                f"Model response: {step.model_response[:500]}",
                        metadata={
                            "detector_name": dr["detector_name"],
                            "confidence": dr["confidence"],
                            "sandbox_job_id": result.job_id,
                        },
                    )

                    severity = Severity.HIGH if dr["confidence"] > 0.8 else base_severity

                    finding = Finding(
                        title=f"Sandbox: {dr['detector_name']} detected vulnerability",
                        description=(
                            f"Detector '{dr['detector_name']}' flagged a vulnerability "
                            f"during sandbox scenario '{self.scenario.name}' at turn "
                            f"{step.turn_number} with confidence {dr['confidence']:.2f}."
                        ),
                        severity=severity,
                        category=base_category,
                        component_type=ComponentType.MODEL,
                        component_name=self.runner.model,
                        evidence=[evidence],
                        confidence=dr["confidence"],
                        tags=["sandbox", "detector", dr["detector_name"]],
                        metadata={
                            "sandbox_scenario": self.scenario.name,
                            "sandbox_job_id": result.job_id,
                            "turn_number": step.turn_number,
                            "detector": dr["detector_name"],
                        },
                        scan_id=result.metadata.get("scan_id"),
                        deployment_id=result.deployment_id,
                    )
                    findings.append(finding)

        return findings

    @staticmethod
    def _estimate_tokens(messages: list[dict[str, str]]) -> int:
        """Rough token estimate (~4 chars per token)."""
        total_chars = sum(len(str(m.get("content", ""))) for m in messages)
        return total_chars // 4
