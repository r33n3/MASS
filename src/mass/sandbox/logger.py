"""Structured telemetry logging for sandbox execution.

Captures per-event telemetry during a sandbox run, enabling
multi-format export, compliance validation, and guardrail generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class TelemetryEvent:
    """Single telemetry event in the sandbox run log."""

    timestamp: datetime
    event_type: str  # turn_start | prompt_assembled | model_called
    # | tool_requested | tool_resolved | memory_read
    # | memory_write | assertion_check | detector_run
    # | turn_complete | scenario_complete
    turn_number: int
    data: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None
    component: str | None = None  # model | tool | memory | router

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "turn_number": self.turn_number,
            "data": self.data,
            "severity": self.severity,
            "component": self.component,
        }


@dataclass
class SandboxTelemetry:
    """Complete telemetry log for a sandbox run."""

    job_id: str
    scenario_name: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    events: list[TelemetryEvent] = field(default_factory=list)

    # Aggregate metrics
    total_tokens: int = 0
    total_tool_calls: int = 0
    total_memory_ops: int = 0
    total_latency_ms: float = 0.0
    model_calls: int = 0

    def append(self, event: TelemetryEvent) -> None:
        self.events.append(event)

    def filter_by_type(self, event_type: str) -> list[TelemetryEvent]:
        return [e for e in self.events if e.event_type == event_type]

    def filter_by_turn(self, turn: int) -> list[TelemetryEvent]:
        return [e for e in self.events if e.turn_number == turn]

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "scenario_name": self.scenario_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_tokens": self.total_tokens,
            "total_tool_calls": self.total_tool_calls,
            "total_memory_ops": self.total_memory_ops,
            "total_latency_ms": self.total_latency_ms,
            "model_calls": self.model_calls,
            "events": [e.to_dict() for e in self.events],
        }

    def to_jsonl(self) -> str:
        """Export as newline-delimited JSON (one event per line)."""
        import json

        lines = []
        for event in self.events:
            lines.append(json.dumps(event.to_dict(), default=str))
        return "\n".join(lines)


class SandboxLogger:
    """Captures structured telemetry during sandbox execution."""

    def __init__(self, job_id: str, scenario_name: str) -> None:
        self.telemetry = SandboxTelemetry(
            job_id=job_id,
            scenario_name=scenario_name,
            started_at=datetime.utcnow(),
        )

    def log(
        self,
        event_type: str,
        turn: int,
        data: dict[str, Any] | None = None,
        severity: str | None = None,
        component: str | None = None,
    ) -> None:
        """Log a telemetry event."""
        self.telemetry.append(TelemetryEvent(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            turn_number=turn,
            data=data or {},
            severity=severity,
            component=component,
        ))

    def log_turn_start(self, turn: int, user_input: str, memory_state: dict[str, Any]) -> None:
        self.log("turn_start", turn, {
            "user_input": user_input,
            "memory_keys": list(memory_state.keys()),
        })

    def log_prompt_assembled(self, turn: int, message_count: int, token_estimate: int) -> None:
        self.log("prompt_assembled", turn, {
            "message_count": message_count,
            "token_estimate": token_estimate,
        }, component="model")

    def log_model_called(
        self,
        turn: int,
        provider: str,
        model: str,
        latency_ms: float,
        tokens: int,
        temperature: float,
    ) -> None:
        self.telemetry.model_calls += 1
        self.telemetry.total_tokens += tokens
        self.telemetry.total_latency_ms += latency_ms
        self.log("model_called", turn, {
            "provider": provider,
            "model": model,
            "latency_ms": latency_ms,
            "tokens": tokens,
            "temperature": temperature,
        }, component="model")

    def log_tool_requested(self, turn: int, tool_name: str, arguments: dict[str, Any]) -> None:
        self.telemetry.total_tool_calls += 1
        self.log("tool_requested", turn, {
            "tool_name": tool_name,
            "arguments": arguments,
        }, component="tool")

    def log_tool_resolved(
        self, turn: int, tool_name: str, mode: str, response: dict[str, Any],
    ) -> None:
        self.log("tool_resolved", turn, {
            "tool_name": tool_name,
            "mode": mode,
            "response_preview": str(response)[:500],
        }, component="tool")

    def log_memory_write(
        self, turn: int, key: str, old_value: Any, new_value: Any,
    ) -> None:
        self.telemetry.total_memory_ops += 1
        self.log("memory_write", turn, {
            "key": key,
            "old_value": str(old_value)[:200] if old_value is not None else None,
            "new_value": str(new_value)[:200] if new_value is not None else None,
        }, component="memory")

    def log_assertion_check(
        self,
        turn: int,
        assertion_type: str,
        target: str,
        passed: bool,
        expected: str | None = None,
        actual: str | None = None,
    ) -> None:
        self.log("assertion_check", turn, {
            "assertion_type": assertion_type,
            "target": target,
            "passed": passed,
            "expected": expected,
            "actual": actual[:200] if actual else None,
        }, severity="info" if passed else "medium")

    def log_detector_run(
        self,
        turn: int,
        detector_name: str,
        status: str,
        confidence: float,
        evidence: list[str] | None = None,
    ) -> None:
        self.log("detector_run", turn, {
            "detector_name": detector_name,
            "status": status,
            "confidence": confidence,
            "evidence": evidence or [],
        }, severity="high" if status == "vulnerable" else None, component="model")

    def log_turn_complete(
        self, turn: int, response_preview: str, cumulative_tokens: int,
    ) -> None:
        self.log("turn_complete", turn, {
            "response_preview": response_preview[:300],
            "cumulative_tokens": cumulative_tokens,
        })

    def finalize(self) -> SandboxTelemetry:
        """Mark run complete and return telemetry."""
        self.telemetry.completed_at = datetime.utcnow()
        self.log("scenario_complete", -1, {
            "total_tokens": self.telemetry.total_tokens,
            "total_tool_calls": self.telemetry.total_tool_calls,
            "total_memory_ops": self.telemetry.total_memory_ops,
            "model_calls": self.telemetry.model_calls,
            "total_latency_ms": self.telemetry.total_latency_ms,
        })
        return self.telemetry
