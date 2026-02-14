"""Scenario packs — curated collections of generic security test scenarios.

Packs are pre-built test suites organized by security domain that can be
run against any AI application without project-specific configuration.
Each pack groups related scenarios from ``scenarios/*.yaml``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mass.sandbox.scenario import Scenario, load_builtin_scenario

logger = logging.getLogger(__name__)

SCENARIOS_DIR = Path(__file__).parent / "scenarios"


@dataclass
class ScenarioPack:
    """A curated collection of security test scenarios."""

    id: str
    name: str
    description: str
    domain: str
    difficulty: str  # basic | intermediate | advanced
    scenario_names: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    recommended_for: list[str] = field(default_factory=list)
    icon: str = ""  # emoji or icon class for UI

    @property
    def estimated_turns(self) -> int:
        """Estimate total turns by loading scenario metadata."""
        total = 0
        for name in self.scenario_names:
            scenario = load_builtin_scenario(name)
            if scenario:
                total += len(scenario.turns)
        return total

    def load_scenarios(self) -> list[Scenario]:
        """Load all scenarios in this pack."""
        scenarios: list[Scenario] = []
        for name in self.scenario_names:
            scenario = load_builtin_scenario(name)
            if scenario:
                scenarios.append(scenario)
            else:
                logger.warning("Pack %s: scenario '%s' not found", self.id, name)
        return scenarios

    def to_dict(self) -> dict[str, Any]:
        """Serialize pack metadata (without loading full scenarios)."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "domain": self.domain,
            "difficulty": self.difficulty,
            "scenario_count": len(self.scenario_names),
            "scenario_names": self.scenario_names,
            "tags": self.tags,
            "recommended_for": self.recommended_for,
            "estimated_turns": self.estimated_turns,
            "icon": self.icon,
        }


# ── Pack Registry ────────────────────────────────────────────────────

PACKS: dict[str, ScenarioPack] = {
    "prompt-injection": ScenarioPack(
        id="prompt-injection",
        name="Prompt Injection Resistance",
        description="Tests model resistance to direct and indirect prompt injection attacks including instruction override, delimiter escape, and persona shift.",
        domain="prompt_safety",
        difficulty="basic",
        scenario_names=[
            "System Prompt Boundary Testing",
            "Generic Prompt Injection Resistance",
            "Advanced Prompt Injection Techniques",
        ],
        tags=["prompt_injection", "owasp_llm01", "instruction_override"],
        recommended_for=["chatbot", "agent", "rag", "copilot"],
        icon="shield",
    ),
    "tool-safety": ScenarioPack(
        id="tool-safety",
        name="Tool Safety",
        description="Tests whether tools can be abused through argument injection, cross-tool manipulation, path traversal, and SSRF attacks.",
        domain="tool_security",
        difficulty="intermediate",
        scenario_names=[
            "Tool Argument Injection",
            "Adversarial Tool Responses",
            "Generic Tool Abuse Scenarios",
        ],
        tags=["tool_abuse", "injection", "owasp_llm06", "excessive_agency"],
        recommended_for=["agent", "copilot", "mcp_server"],
        icon="wrench",
    ),
    "system-prompt-protection": ScenarioPack(
        id="system-prompt-protection",
        name="System Prompt Protection",
        description="Tests resistance to system prompt extraction via direct requests, summarization tricks, encoding transforms, and completion hijacking.",
        domain="information_leak",
        difficulty="basic",
        scenario_names=[
            "System Prompt Extraction Attacks",
            "System Prompt Encoding Bypass",
        ],
        tags=["system_prompt_leakage", "information_disclosure", "encoding_bypass"],
        recommended_for=["chatbot", "agent", "rag", "copilot"],
        icon="lock",
    ),
    "jailbreak": ScenarioPack(
        id="jailbreak",
        name="Jailbreak & Bypass",
        description="Tests resistance to jailbreak attempts including DAN, role-play bypass, hypothetical framing, encoded payloads, and multi-step attacks.",
        domain="model_safety",
        difficulty="advanced",
        scenario_names=[
            "Jailbreak and Safety Bypass",
            "Encoded Jailbreak Attempts",
        ],
        tags=["jailbreak", "model_safety", "encoding_bypass"],
        recommended_for=["chatbot", "agent", "copilot"],
        icon="skull",
    ),
    "data-leakage": ScenarioPack(
        id="data-leakage",
        name="Data Leakage Prevention",
        description="Tests whether the model properly protects sensitive data including PII masking, credential protection, and preventing exfiltration via tools.",
        domain="data_safety",
        difficulty="intermediate",
        scenario_names=[
            "Data Exfiltration via Tools",
            "PII Leakage Prevention",
        ],
        tags=["data_leakage", "pii", "exfiltration", "privacy"],
        recommended_for=["agent", "rag", "copilot", "customer_service"],
        icon="database",
    ),
    "context-safety": ScenarioPack(
        id="context-safety",
        name="Memory & Context Poisoning",
        description="Tests resistance to context manipulation, fake history injection, memory poisoning, and indirect instruction injection via stored data.",
        domain="context_safety",
        difficulty="intermediate",
        scenario_names=[
            "Memory Poisoning and Data Leakage",
            "Context and Memory Manipulation",
        ],
        tags=["context_manipulation", "memory_poisoning", "indirect_injection"],
        recommended_for=["agent", "rag", "copilot"],
        icon="brain",
    ),
    "access-control": ScenarioPack(
        id="access-control",
        name="Routing & Authorization",
        description="Tests enforcement of authorization boundaries, privilege escalation resistance, unauthorized tool access, and multi-tenant isolation.",
        domain="access_control",
        difficulty="advanced",
        scenario_names=[
            "Routing and Skill Abuse",
            "Privilege Escalation and Authorization Bypass",
        ],
        tags=["privilege_escalation", "authorization", "routing", "access_control"],
        recommended_for=["agent", "mcp_server", "multi_tenant"],
        icon="key",
    ),
}


def list_packs() -> list[dict[str, Any]]:
    """Return metadata for all available packs."""
    return [pack.to_dict() for pack in PACKS.values()]


def get_pack(pack_id: str) -> ScenarioPack | None:
    """Get a specific pack by ID."""
    return PACKS.get(pack_id)
