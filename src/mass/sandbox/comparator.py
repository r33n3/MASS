"""Run-to-run comparison for sandbox results.

Compares two sandbox runs (same scenario, different points in time) to
track whether issues have been fixed or new ones introduced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FindingDelta:
    """Change in a single finding between two runs."""

    finding_title: str
    category: str
    severity: str
    status: str  # resolved | persists | new | regressed
    baseline_turn: int | None = None
    current_turn: int | None = None
    evidence_diff: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "baseline_turn": self.baseline_turn,
            "current_turn": self.current_turn,
            "evidence_diff": self.evidence_diff,
        }


@dataclass
class ComparisonResult:
    """Full diff between two sandbox runs."""

    baseline_job_id: str
    current_job_id: str
    scenario_name: str

    # Score delta
    baseline_score: float = 0.0
    current_score: float = 0.0
    score_delta: float = 0.0

    # Finding changes
    resolved: list[FindingDelta] = field(default_factory=list)
    persists: list[FindingDelta] = field(default_factory=list)
    new_issues: list[FindingDelta] = field(default_factory=list)
    regressions: list[FindingDelta] = field(default_factory=list)

    # Assertion changes
    assertions_fixed: list[str] = field(default_factory=list)
    assertions_broken: list[str] = field(default_factory=list)
    assertions_unchanged: int = 0

    # Per-turn diff
    turn_diffs: list[dict[str, Any]] = field(default_factory=list)

    # Compliance changes
    compliance_improved: list[dict[str, Any]] = field(default_factory=list)
    compliance_regressed: list[dict[str, Any]] = field(default_factory=list)

    # Guardrail effectiveness
    guardrails_validated: list[dict[str, Any]] = field(default_factory=list)

    @property
    def improved(self) -> bool:
        return self.score_delta > 0 and len(self.new_issues) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": {
                "job_id": self.baseline_job_id,
                "score": self.baseline_score,
            },
            "current": {
                "job_id": self.current_job_id,
                "score": self.current_score,
            },
            "scenario_name": self.scenario_name,
            "score_delta": round(self.score_delta, 2),
            "improved": self.improved,
            "resolved": [d.to_dict() for d in self.resolved],
            "persists": [d.to_dict() for d in self.persists],
            "new_issues": [d.to_dict() for d in self.new_issues],
            "regressions": [d.to_dict() for d in self.regressions],
            "assertions_fixed": self.assertions_fixed,
            "assertions_broken": self.assertions_broken,
            "assertions_unchanged": self.assertions_unchanged,
            "turn_diffs": self.turn_diffs,
            "compliance_improved": self.compliance_improved,
            "compliance_regressed": self.compliance_regressed,
            "guardrails_validated": self.guardrails_validated,
        }


class SandboxComparator:
    """Compares two sandbox runs to track remediation progress."""

    def compare(
        self,
        baseline: Any,  # SandboxResult
        current: Any,  # SandboxResult
        baseline_score: float = 0.0,
        current_score: float = 0.0,
    ) -> ComparisonResult:
        """Diff two runs of the same scenario."""
        result = ComparisonResult(
            baseline_job_id=baseline.job_id,
            current_job_id=current.job_id,
            scenario_name=baseline.scenario_name,
            baseline_score=baseline_score,
            current_score=current_score,
            score_delta=current_score - baseline_score,
        )

        # Match findings
        resolved, persists, new_issues = self._match_findings(
            baseline.findings, current.findings,
        )
        result.resolved = resolved
        result.persists = persists
        result.new_issues = new_issues

        # Match assertions
        result.assertions_fixed, result.assertions_broken, result.assertions_unchanged = (
            self._match_assertions(baseline.steps, current.steps)
        )

        # Per-turn diff
        result.turn_diffs = self._diff_turns(baseline.steps, current.steps)

        return result

    def _match_findings(
        self,
        baseline_findings: list,
        current_findings: list,
    ) -> tuple[list[FindingDelta], list[FindingDelta], list[FindingDelta]]:
        """Match findings between runs using title+category fingerprint."""
        resolved = []
        persists = []
        new_issues = []

        # Build fingerprint maps
        def _fingerprint(finding: Any) -> str:
            title = finding.title if hasattr(finding, "title") else str(finding.get("title", ""))
            cat = finding.category.value if hasattr(finding.category, "value") else str(finding.get("category", ""))
            return f"{title}|{cat}"

        baseline_map: dict[str, Any] = {}
        for f in baseline_findings:
            fp = _fingerprint(f)
            baseline_map[fp] = f

        current_map: dict[str, Any] = {}
        for f in current_findings:
            fp = _fingerprint(f)
            current_map[fp] = f

        # Findings in baseline but not in current → resolved
        for fp, finding in baseline_map.items():
            title = finding.title if hasattr(finding, "title") else str(finding.get("title", ""))
            cat = finding.category.value if hasattr(finding.category, "value") else str(finding.get("category", ""))
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.get("severity", ""))
            turn = finding.metadata.get("turn_number") if hasattr(finding, "metadata") else None

            if fp not in current_map:
                resolved.append(FindingDelta(
                    finding_title=title,
                    category=cat,
                    severity=sev,
                    status="resolved",
                    baseline_turn=turn,
                    current_turn=None,
                ))
            else:
                persists.append(FindingDelta(
                    finding_title=title,
                    category=cat,
                    severity=sev,
                    status="persists",
                    baseline_turn=turn,
                    current_turn=(
                        current_map[fp].metadata.get("turn_number")
                        if hasattr(current_map[fp], "metadata") else None
                    ),
                ))

        # Findings in current but not in baseline → new
        for fp, finding in current_map.items():
            if fp not in baseline_map:
                title = finding.title if hasattr(finding, "title") else str(finding.get("title", ""))
                cat = finding.category.value if hasattr(finding.category, "value") else str(finding.get("category", ""))
                sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.get("severity", ""))
                turn = finding.metadata.get("turn_number") if hasattr(finding, "metadata") else None

                new_issues.append(FindingDelta(
                    finding_title=title,
                    category=cat,
                    severity=sev,
                    status="new",
                    baseline_turn=None,
                    current_turn=turn,
                ))

        return resolved, persists, new_issues

    def _match_assertions(
        self,
        baseline_steps: list,
        current_steps: list,
    ) -> tuple[list[str], list[str], int]:
        """Match assertions between runs."""
        fixed = []
        broken = []
        unchanged = 0

        # Collect all assertions from each run
        baseline_failed = set()
        baseline_passed = set()
        for step in baseline_steps:
            for a in step.assertions_failed:
                baseline_failed.add(f"turn{step.turn_number}:{a}")
            for a in step.assertions_passed:
                baseline_passed.add(f"turn{step.turn_number}:{a}")

        current_failed = set()
        current_passed = set()
        for step in current_steps:
            for a in step.assertions_failed:
                current_failed.add(f"turn{step.turn_number}:{a}")
            for a in step.assertions_passed:
                current_passed.add(f"turn{step.turn_number}:{a}")

        # Was failing, now passing
        fixed = sorted(baseline_failed & current_passed)
        # Was passing, now failing
        broken = sorted(baseline_passed & current_failed)
        # Count unchanged
        unchanged = len(
            (baseline_passed & current_passed) | (baseline_failed & current_failed)
        )

        return fixed, broken, unchanged

    def _diff_turns(
        self,
        baseline_steps: list,
        current_steps: list,
    ) -> list[dict[str, Any]]:
        """Per-turn comparison."""
        diffs = []
        max_turns = max(len(baseline_steps), len(current_steps))

        for i in range(max_turns):
            diff: dict[str, Any] = {"turn": i}

            if i < len(baseline_steps) and i < len(current_steps):
                bs = baseline_steps[i]
                cs = current_steps[i]

                # Compare tool calls
                b_tools = sorted(tc.name for tc in bs.tool_calls_made)
                c_tools = sorted(tc.name for tc in cs.tool_calls_made)
                diff["tools_changed"] = b_tools != c_tools
                diff["baseline_tools"] = b_tools
                diff["current_tools"] = c_tools

                # Compare assertion outcomes
                diff["assertions_changed"] = (
                    set(bs.assertions_failed) != set(cs.assertions_failed)
                    or set(bs.assertions_passed) != set(cs.assertions_passed)
                )

                # Compare memory
                diff["memory_changed"] = bs.memory_after != cs.memory_after

                # Response similarity (simple length comparison)
                diff["response_length_delta"] = len(cs.model_response) - len(bs.model_response)

            elif i < len(baseline_steps):
                diff["status"] = "removed_in_current"
            else:
                diff["status"] = "added_in_current"

            diffs.append(diff)

        return diffs
