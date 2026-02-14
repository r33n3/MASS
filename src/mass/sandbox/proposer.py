"""Scenario proposer — analyzes targets and proposes tailored test scenarios.

Given a discovered :class:`TargetSurface`, the proposer assesses risks,
generates :class:`ScenarioProposal` objects with rationale and priority,
and lets the user approve before executing.  This is the "Project Analysis"
mode of the sandbox — targeted security validation of specific projects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from mass.sandbox.binder import CorpusBinder
from mass.sandbox.corpus.payloads import (
    CATEGORY_SEVERITY,
    Payload,
    infer_attack_categories,
)
from mass.sandbox.corpus import CorpusLoader
from mass.sandbox.profiles import PROFILES, TestProfile
from mass.sandbox.scenario import Scenario
from mass.sandbox.surface import TargetSurface, ToolSurface, ModelSurface, InstructionSurface

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────────


@dataclass
class ScenarioProposal:
    """A single proposed scenario with rationale."""

    id: str
    scenario_name: str
    description: str = ""
    rationale: str = ""
    priority: str = "medium"  # critical | high | medium | low
    category: str = ""
    risk_factors: list[str] = field(default_factory=list)
    estimated_turns: int = 0
    approved: bool = False

    # Internal: surface refs for generating the actual scenario
    _surface_type: str = ""  # "tool", "model", "instruction"
    _surface_index: int = 0
    _attack_categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scenario_name": self.scenario_name,
            "description": self.description,
            "rationale": self.rationale,
            "priority": self.priority,
            "category": self.category,
            "risk_factors": self.risk_factors,
            "estimated_turns": self.estimated_turns,
            "approved": self.approved,
        }


@dataclass
class ProposalReport:
    """Complete proposal report for a target."""

    proposal_id: str
    target_type: str = ""
    target_summary: dict[str, Any] = field(default_factory=dict)
    risk_assessment: list[str] = field(default_factory=list)
    proposals: list[ScenarioProposal] = field(default_factory=list)
    recommended_profile: str = "standard"
    coverage_estimate: str = ""

    # Internal: keep surface for execution
    _surface: TargetSurface | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "target_type": self.target_type,
            "target_summary": self.target_summary,
            "risk_assessment": self.risk_assessment,
            "proposals": [p.to_dict() for p in self.proposals],
            "recommended_profile": self.recommended_profile,
            "coverage_estimate": self.coverage_estimate,
        }


# ── Risk assessment heuristics ──────────────────────────────────────


# Descriptions of why each category matters for a tool
_TOOL_RISK_RATIONALE: dict[str, str] = {
    "command_injection": (
        "Tool accepts command-like input that could be used to execute "
        "arbitrary system commands if not properly sanitized."
    ),
    "path_traversal": (
        "Tool handles file paths that could be manipulated to access "
        "files outside the intended directory."
    ),
    "ssrf": (
        "Tool accepts URLs that could be abused to access internal "
        "services or cloud metadata endpoints."
    ),
    "sql_injection": (
        "Tool processes query-like input that could be exploited to "
        "manipulate database operations."
    ),
    "prompt_injection": (
        "Tool accepts freeform text that could contain hidden instructions "
        "to manipulate the model's behavior."
    ),
    "template_injection": (
        "Tool handles template-like content that could execute arbitrary "
        "expressions if parsed unsafely."
    ),
    "boundary": (
        "Tool parameters should be tested for boundary conditions like "
        "oversized inputs, null values, and special characters."
    ),
    "exfiltration": (
        "Tool handles data that could be used as a channel to leak "
        "sensitive information from the system."
    ),
    "privilege_escalation": (
        "Tool processes structured data that could be crafted to "
        "escalate privileges or bypass access controls."
    ),
    "information_disclosure": (
        "Tool may inadvertently expose internal system information "
        "through error messages or verbose responses."
    ),
}

_MODEL_RISK_RATIONALE: dict[str, str] = {
    "jailbreak": "Model should be tested for resistance to common jailbreak techniques.",
    "system_prompt_extraction": "Model should not leak its system prompt when probed.",
    "instruction_override": "Model should refuse attempts to override its instructions.",
    "harmful_content": "Model should refuse requests for harmful or dangerous content.",
    "encoding_bypass": "Model should resist attempts to bypass safety via encoding tricks.",
}

_INSTRUCTION_RISK_RATIONALE: dict[str, str] = {
    "boundary_enforcement": "Instruction rules should hold under adversarial pressure.",
    "rule_violation": "Explicit rules should not be circumvented via social engineering.",
    "context_manipulation": "Model should not accept fake authorization claims.",
    "persona_break": "Model should maintain its assigned persona under pressure.",
}


# ── Proposer ────────────────────────────────────────────────────────


class ScenarioProposer:
    """Analyzes target surfaces and proposes tailored test scenarios."""

    def __init__(self, profile: TestProfile | None = None) -> None:
        self.profile = profile or PROFILES["standard"]
        self._loader = CorpusLoader()

    def propose(self, surface: TargetSurface, target_type: str = "") -> ProposalReport:
        """Analyze surface and generate a proposal report."""
        proposal_id = str(uuid4())

        # Build target summary
        target_summary = {
            "tools": [{"name": t.name, "description": t.description, "source": t.source} for t in surface.tools],
            "models": [{"provider": m.provider, "model": m.model, "source": m.source} for m in surface.models],
            "instructions": [{"source": i.source, "rules_count": len(i.rules)} for i in surface.instructions],
        }

        # Assess risks
        risk_assessment: list[str] = []
        proposals: list[ScenarioProposal] = []

        # Tool proposals
        for i, tool in enumerate(surface.tools):
            tool_proposals, tool_risks = self._propose_for_tool(tool, i)
            proposals.extend(tool_proposals)
            risk_assessment.extend(tool_risks)

        # Model proposals
        for i, model in enumerate(surface.models):
            model_proposals, model_risks = self._propose_for_model(model, i)
            proposals.extend(model_proposals)
            risk_assessment.extend(model_risks)

        # Instruction proposals
        for i, instruction in enumerate(surface.instructions):
            inst_proposals, inst_risks = self._propose_for_instruction(instruction, i)
            proposals.extend(inst_proposals)
            risk_assessment.extend(inst_risks)

        # Recommend profile based on surface complexity
        recommended_profile = self._recommend_profile(surface)

        # Coverage estimate
        total_cats = len({p.category for p in proposals})
        total_turns = sum(p.estimated_turns for p in proposals)
        coverage_estimate = (
            f"{len(proposals)} scenarios across {total_cats} categories, "
            f"~{total_turns} attack vectors"
        )

        # Sort proposals by priority
        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        proposals.sort(key=lambda p: prio_order.get(p.priority, 99))

        report = ProposalReport(
            proposal_id=proposal_id,
            target_type=target_type,
            target_summary=target_summary,
            risk_assessment=risk_assessment,
            proposals=proposals,
            recommended_profile=recommended_profile,
            coverage_estimate=coverage_estimate,
        )
        report._surface = surface
        return report

    def execute_approved(self, report: ProposalReport) -> list[Scenario]:
        """Generate Scenario objects for approved proposals only."""
        if not report._surface:
            return []

        approved = [p for p in report.proposals if p.approved]
        if not approved:
            return []

        binder = CorpusBinder(self.profile)

        # Group approved proposals by surface type
        tool_indices = {p._surface_index for p in approved if p._surface_type == "tool"}
        model_indices = {p._surface_index for p in approved if p._surface_type == "model"}
        instruction_indices = {p._surface_index for p in approved if p._surface_type == "instruction"}

        scenarios: list[Scenario] = []

        # Generate tool scenarios (pass instructions for system prompt context)
        if tool_indices:
            selected_tools = [
                report._surface.tools[i]
                for i in tool_indices
                if i < len(report._surface.tools)
            ]
            scenarios.extend(
                binder.bind_tools(selected_tools, report._surface.instructions)
            )

        # Generate model scenarios
        if model_indices:
            selected_models = [
                report._surface.models[i]
                for i in model_indices
                if i < len(report._surface.models)
            ]
            scenarios.extend(binder.bind_models(selected_models))

        # Generate instruction scenarios
        if instruction_indices:
            selected_instructions = [
                report._surface.instructions[i]
                for i in instruction_indices
                if i < len(report._surface.instructions)
            ]
            scenarios.extend(
                binder.bind_instructions(selected_instructions, report._surface.models)
            )

        return scenarios

    # ── Internal ────────────────────────────────────────────────────

    def _propose_for_tool(
        self, tool: ToolSurface, index: int,
    ) -> tuple[list[ScenarioProposal], list[str]]:
        """Generate proposals for a single tool."""
        proposals: list[ScenarioProposal] = []
        risks: list[str] = []

        # Collect all applicable categories across params
        all_categories: set[str] = set()
        risk_factors: list[str] = []

        for param in tool.parameters:
            cats = infer_attack_categories(
                param.get("name", ""),
                param.get("type", "string"),
                param.get("description", ""),
            )
            for cat in cats:
                all_categories.add(cat)
                risk_factors.append(
                    f"Parameter '{param.get('name', '?')}' is susceptible to {cat}"
                )

        if not all_categories:
            all_categories = {"boundary", "prompt_injection"}
            risk_factors.append("Generic string parameters detected")

        # Risk assessment
        critical_cats = [c for c in all_categories if CATEGORY_SEVERITY.get(c) == "critical"]
        if critical_cats:
            risks.append(
                f"Tool '{tool.name}' has critical risk exposure: "
                f"{', '.join(critical_cats)}"
            )

        # One proposal per applicable category
        corpus = self._loader.load_tool_corpus()
        for cat in sorted(all_categories):
            payloads = corpus.get(cat, [])
            if not payloads:
                continue

            severity = CATEGORY_SEVERITY.get(cat, "medium")
            count = min(len(payloads), self.profile.max_payloads_per_category)
            cat_risk_factors = [f for f in risk_factors if cat in f]

            proposals.append(ScenarioProposal(
                id=str(uuid4()),
                scenario_name=f"{tool.name}: {cat.replace('_', ' ').title()} Testing",
                description=(
                    f"Test '{tool.name}' against {count} {cat.replace('_', ' ')} "
                    f"payloads targeting vulnerable parameters."
                ),
                rationale=_TOOL_RISK_RATIONALE.get(cat, f"Test {cat} attack vectors."),
                priority=severity,
                category=cat,
                risk_factors=cat_risk_factors[:3],
                estimated_turns=count + 1,  # +1 for baseline
                _surface_type="tool",
                _surface_index=index,
                _attack_categories=[cat],
            ))

        return proposals, risks

    def _propose_for_model(
        self, model: ModelSurface, index: int,
    ) -> tuple[list[ScenarioProposal], list[str]]:
        """Generate proposals for a model endpoint."""
        proposals: list[ScenarioProposal] = []
        risks: list[str] = [
            f"Model endpoint {model.provider}/{model.model} will be tested "
            f"for safety compliance and resistance to adversarial inputs."
        ]

        corpus = self._loader.load_model_corpus()
        for cat, payloads in corpus.items():
            count = min(len(payloads), self.profile.max_payloads_per_category)

            proposals.append(ScenarioProposal(
                id=str(uuid4()),
                scenario_name=f"{model.model}: {cat.replace('_', ' ').title()} Testing",
                description=(
                    f"Test model {model.provider}/{model.model} against "
                    f"{count} {cat.replace('_', ' ')} payloads."
                ),
                rationale=_MODEL_RISK_RATIONALE.get(
                    cat, f"Test model behavior against {cat} attacks."
                ),
                priority="high" if cat in ("jailbreak", "system_prompt_extraction") else "medium",
                category=cat,
                risk_factors=[f"Model type: {model.provider}/{model.model}"],
                estimated_turns=count + 1,
                _surface_type="model",
                _surface_index=index,
                _attack_categories=[cat],
            ))

        return proposals, risks

    def _propose_for_instruction(
        self, instruction: InstructionSurface, index: int,
    ) -> tuple[list[ScenarioProposal], list[str]]:
        """Generate proposals for an instruction set."""
        proposals: list[ScenarioProposal] = []
        risks: list[str] = []

        if instruction.rules:
            risks.append(
                f"Instruction set ({instruction.source}) has "
                f"{len(instruction.rules)} explicit rules to test."
            )
        else:
            risks.append(
                f"Instruction set ({instruction.source}) has no explicit "
                f"rules — testing general adherence."
            )

        corpus = self._loader.load_instruction_corpus()
        for cat, payloads in corpus.items():
            count = min(len(payloads), self.profile.max_payloads_per_category)

            proposals.append(ScenarioProposal(
                id=str(uuid4()),
                scenario_name=f"Instruction ({instruction.source}): {cat.replace('_', ' ').title()}",
                description=(
                    f"Test instruction adherence against {count} "
                    f"{cat.replace('_', ' ')} payloads."
                ),
                rationale=_INSTRUCTION_RISK_RATIONALE.get(
                    cat, f"Test instruction resilience against {cat} attacks."
                ),
                priority="high" if cat == "rule_violation" and instruction.rules else "medium",
                category=cat,
                risk_factors=[f"{len(instruction.rules)} rules extracted"],
                estimated_turns=count + 1,
                _surface_type="instruction",
                _surface_index=index,
                _attack_categories=[cat],
            ))

        return proposals, risks

    def _recommend_profile(self, surface: TargetSurface) -> str:
        """Recommend a test profile based on surface complexity."""
        total_components = len(surface.tools) + len(surface.models) + len(surface.instructions)

        if total_components <= 2:
            return "comprehensive"
        elif total_components <= 5:
            return "standard"
        else:
            return "quick"
