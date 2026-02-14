"""AI Application Security Sandbox.

Provides a controlled local environment to replicate an AI application's
runtime (system prompts, tools, routing, memory) and run repeatable
security tests against it.
"""

from mass.sandbox.comparator import ComparisonResult, FindingDelta, SandboxComparator
from mass.sandbox.logger import SandboxLogger, SandboxTelemetry, TelemetryEvent
from mass.sandbox.reporter import SandboxReport, SandboxReportFormat, SandboxReporter
from mass.sandbox.runtime import SandboxResult, SandboxRuntime, StepState
from mass.sandbox.scenario import (
    Assertion,
    MemoryOp,
    Scenario,
    ScenarioTurn,
    ToolMock,
    list_builtin_scenarios,
    load_builtin_scenario,
)
from mass.sandbox.scorer import SandboxScorer, ScenarioScore

__all__ = [
    # Scenario
    "Scenario",
    "ScenarioTurn",
    "ToolMock",
    "MemoryOp",
    "Assertion",
    "list_builtin_scenarios",
    "load_builtin_scenario",
    # Runtime
    "SandboxRuntime",
    "SandboxResult",
    "StepState",
    # Scoring
    "SandboxScorer",
    "ScenarioScore",
    # Logging
    "SandboxLogger",
    "SandboxTelemetry",
    "TelemetryEvent",
    # Reporting
    "SandboxReporter",
    "SandboxReport",
    "SandboxReportFormat",
    # Comparison
    "SandboxComparator",
    "ComparisonResult",
    "FindingDelta",
]
