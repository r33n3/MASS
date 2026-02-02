"""Main policy engine that ties everything together.

Analyzes findings, generates recommendations, creates
remediation plans, and produces policy reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mass.core.findings import Finding
from mass.core.types import AttackCategory, Severity
from mass.policy.guardrails import (
    Guardrail,
    GuardrailRegistry,
    GuardrailSeverity,
    get_default_guardrails,
)
from mass.policy.recommendations import (
    Recommendation,
    RecommendationEngine,
    RecommendationPriority,
)
from mass.policy.templates import (
    PolicyTemplate,
    PolicyRegistry,
    get_policy_templates,
)
from mass.policy.remediation import (
    RemediationPlan,
    create_remediation_plan,
    generate_remediation_report,
)


@dataclass
class PolicyEngineConfig:
    """Configuration for the policy engine."""

    # Include options
    include_guardrails: bool = True
    include_recommendations: bool = True
    include_policy_templates: bool = True
    include_remediation_plan: bool = True

    # Filtering
    min_severity: Severity = Severity.LOW
    max_recommendations_per_category: int = 3
    include_mitigations: bool = True

    # Output options
    generate_markdown_report: bool = True


@dataclass
class GuardrailViolation:
    """A guardrail that is not currently implemented."""

    guardrail: Guardrail
    related_findings: list[Finding] = field(default_factory=list)
    priority: str = "high"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "guardrail": self.guardrail.to_dict(),
            "related_findings": [f.id for f in self.related_findings],
            "priority": self.priority,
        }


@dataclass
class PolicyReport:
    """Complete policy analysis report."""

    scan_id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)

    # Input analysis
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)

    # Guardrails
    required_guardrails: list[Guardrail] = field(default_factory=list)
    guardrail_violations: list[GuardrailViolation] = field(default_factory=list)

    # Recommendations
    recommendations: list[Recommendation] = field(default_factory=list)
    immediate_actions: list[Recommendation] = field(default_factory=list)

    # Policy templates
    recommended_policies: list[PolicyTemplate] = field(default_factory=list)

    # Remediation plan
    remediation_plan: RemediationPlan | None = None

    # Compliance
    compliance_gaps: list[str] = field(default_factory=list)

    # Summary scores
    risk_score: float = 0.0  # 0-100
    remediation_effort_hours: float = 0.0

    # Reports
    markdown_report: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at.isoformat(),
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "required_guardrails": [g.to_dict() for g in self.required_guardrails],
            "guardrail_violations": [v.to_dict() for v in self.guardrail_violations],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "immediate_actions": [r.to_dict() for r in self.immediate_actions],
            "recommended_policies": [p.to_dict() for p in self.recommended_policies],
            "remediation_plan": self.remediation_plan.to_dict() if self.remediation_plan else None,
            "compliance_gaps": self.compliance_gaps,
            "risk_score": self.risk_score,
            "remediation_effort_hours": self.remediation_effort_hours,
        }


class PolicyEngine:
    """Main policy analysis and recommendation engine.

    Analyzes findings and produces comprehensive policy
    recommendations, guardrail requirements, and remediation plans.

    Example:
        engine = PolicyEngine()
        report = engine.analyze(scan_id, findings)

        print(f"Risk Score: {report.risk_score}")
        print(f"Immediate Actions: {len(report.immediate_actions)}")
        print(report.markdown_report)
    """

    def __init__(
        self,
        config: PolicyEngineConfig | None = None,
        guardrail_registry: GuardrailRegistry | None = None,
        policy_registry: PolicyRegistry | None = None,
    ) -> None:
        """Initialize the policy engine.

        Args:
            config: Engine configuration.
            guardrail_registry: Custom guardrail registry.
            policy_registry: Custom policy registry.
        """
        self.config = config or PolicyEngineConfig()
        self.guardrails = guardrail_registry or get_default_guardrails()
        self.policies = policy_registry or get_policy_templates()
        self.recommendation_engine = RecommendationEngine()

    def analyze(
        self,
        scan_id: str,
        findings: list[Finding],
    ) -> PolicyReport:
        """Analyze findings and generate policy report.

        Args:
            scan_id: ID of the scan.
            findings: List of findings to analyze.

        Returns:
            Complete policy report.
        """
        report = PolicyReport(scan_id=scan_id)

        # Filter findings by minimum severity
        filtered_findings = self._filter_findings(findings)

        # Analyze findings
        report.total_findings = len(filtered_findings)
        report.findings_by_severity = self._count_by_severity(filtered_findings)
        report.findings_by_category = self._count_by_category(filtered_findings)

        # Get required guardrails
        if self.config.include_guardrails:
            report.required_guardrails = self._get_required_guardrails(filtered_findings)
            report.guardrail_violations = self._identify_violations(
                filtered_findings,
                report.required_guardrails,
            )

        # Generate recommendations
        if self.config.include_recommendations:
            report.recommendations = self.recommendation_engine.generate(
                filtered_findings,
                include_mitigations=self.config.include_mitigations,
                max_per_category=self.config.max_recommendations_per_category,
            )
            report.immediate_actions = [
                r for r in report.recommendations
                if r.priority == RecommendationPriority.IMMEDIATE
            ]

        # Get recommended policy templates
        if self.config.include_policy_templates:
            report.recommended_policies = self._get_recommended_policies(filtered_findings)

        # Create remediation plan
        if self.config.include_remediation_plan:
            report.remediation_plan = create_remediation_plan(
                scan_id=scan_id,
                findings=filtered_findings,
                recommendations=report.recommendations,
            )
            report.remediation_effort_hours = report.remediation_plan.total_effort_hours

        # Calculate risk score
        report.risk_score = self._calculate_risk_score(filtered_findings)

        # Identify compliance gaps
        report.compliance_gaps = self._identify_compliance_gaps(filtered_findings)

        # Generate markdown report
        if self.config.generate_markdown_report:
            report.markdown_report = self._generate_report(report)

        return report

    def _filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Filter findings by minimum severity."""
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        min_index = severity_order.index(self.config.min_severity)
        allowed_severities = set(severity_order[:min_index + 1])

        return [f for f in findings if f.severity in allowed_severities]

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for f in findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _count_by_category(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by category."""
        counts: dict[str, int] = {}
        for f in findings:
            key = f.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _get_required_guardrails(
        self,
        findings: list[Finding],
    ) -> list[Guardrail]:
        """Get guardrails required based on findings."""
        required: set[str] = set()
        guardrails: list[Guardrail] = []

        for finding in findings:
            related = self.guardrails.get_for_category(finding.category)
            for g in related:
                if g.id not in required:
                    required.add(g.id)
                    guardrails.append(g)

        # Sort by severity
        severity_order = {
            GuardrailSeverity.CRITICAL: 0,
            GuardrailSeverity.HIGH: 1,
            GuardrailSeverity.MEDIUM: 2,
            GuardrailSeverity.LOW: 3,
            GuardrailSeverity.ADVISORY: 4,
        }
        guardrails.sort(key=lambda g: severity_order.get(g.severity, 5))

        return guardrails

    def _identify_violations(
        self,
        findings: list[Finding],
        guardrails: list[Guardrail],
    ) -> list[GuardrailViolation]:
        """Identify which guardrails are being violated."""
        violations = []

        for guardrail in guardrails:
            # Find findings that this guardrail would mitigate
            related = [
                f for f in findings
                if f.category in guardrail.mitigates_categories
            ]

            if related:
                priority = "critical" if guardrail.severity == GuardrailSeverity.CRITICAL else (
                    "high" if guardrail.severity == GuardrailSeverity.HIGH else "medium"
                )
                violations.append(GuardrailViolation(
                    guardrail=guardrail,
                    related_findings=related,
                    priority=priority,
                ))

        return violations

    def _get_recommended_policies(
        self,
        findings: list[Finding],
    ) -> list[PolicyTemplate]:
        """Get recommended policies based on findings."""
        recommended: set[str] = set()
        policies: list[PolicyTemplate] = []

        for finding in findings:
            for policy in self.policies.get_all():
                if finding.category in policy.mitigates:
                    if policy.id not in recommended:
                        recommended.add(policy.id)
                        policies.append(policy)

        return policies

    def _calculate_risk_score(self, findings: list[Finding]) -> float:
        """Calculate overall risk score (0-100)."""
        if not findings:
            return 0.0

        # Weight by severity
        severity_weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 15,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }

        total_weight = sum(severity_weights.get(f.severity, 0) for f in findings)

        # Normalize to 0-100, cap at 100
        score = min(total_weight, 100)

        return score

    def _identify_compliance_gaps(
        self,
        findings: list[Finding],
    ) -> list[str]:
        """Identify compliance framework gaps."""
        gaps = set()

        for finding in findings:
            # Map findings to compliance gaps
            if finding.owasp_ids:
                gaps.update(finding.owasp_ids)
            if finding.cwe_ids:
                gaps.update(f"CWE-{cwe}" for cwe in finding.cwe_ids if not cwe.startswith("CWE"))
                gaps.update(cwe for cwe in finding.cwe_ids if cwe.startswith("CWE"))
            if finding.mitre_ids:
                gaps.update(finding.mitre_ids)

        return sorted(gaps)

    def _generate_report(self, report: PolicyReport) -> str:
        """Generate markdown policy report."""
        lines = [
            "# MASS Policy & Guardrail Report",
            "",
            f"**Scan ID:** {report.scan_id}",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Risk Score:** {report.risk_score:.0f}/100",
            f"- **Total Findings:** {report.total_findings}",
            f"- **Immediate Actions Required:** {len(report.immediate_actions)}",
            f"- **Estimated Remediation Effort:** {report.remediation_effort_hours:.1f} hours",
            "",
        ]

        # Findings by severity
        if report.findings_by_severity:
            lines.extend([
                "### Findings by Severity",
                "",
            ])
            for sev, count in sorted(report.findings_by_severity.items()):
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚫")
                lines.append(f"- {emoji} **{sev.upper()}:** {count}")
            lines.append("")

        # Immediate actions
        if report.immediate_actions:
            lines.extend([
                "## ⚠️ Immediate Actions Required",
                "",
                "The following actions should be taken immediately:",
                "",
            ])
            for i, action in enumerate(report.immediate_actions, 1):
                lines.append(f"### {i}. {action.title}")
                lines.append("")
                lines.append(action.description)
                lines.append("")
                if action.action_steps:
                    lines.append("**Steps:**")
                    for step in action.action_steps:
                        lines.append(f"- {step}")
                    lines.append("")

        # Required guardrails
        if report.guardrail_violations:
            lines.extend([
                "## Required Guardrails",
                "",
                "The following guardrails should be implemented:",
                "",
            ])
            for violation in report.guardrail_violations:
                g = violation.guardrail
                lines.append(f"### 🛡️ {g.name}")
                lines.append("")
                lines.append(f"**Severity:** {g.severity.value.upper()}")
                lines.append(f"**Type:** {g.guardrail_type.value}")
                lines.append(f"**Related Findings:** {len(violation.related_findings)}")
                lines.append("")
                lines.append(g.description)
                lines.append("")
                if g.implementation_steps:
                    lines.append("**Implementation Steps:**")
                    for step in g.implementation_steps:
                        lines.append(f"1. {step}")
                    lines.append("")

        # Recommended policies
        if report.recommended_policies:
            lines.extend([
                "## Recommended Policies",
                "",
            ])
            for policy in report.recommended_policies:
                lines.append(f"### 📋 {policy.name}")
                lines.append("")
                lines.append(policy.description)
                lines.append("")
                lines.append(f"- **Category:** {policy.category.value}")
                lines.append(f"- **Rules:** {len(policy.rules)}")
                lines.append(f"- **Compliance:** {', '.join(policy.compliance_frameworks)}")
                lines.append("")

        # Compliance gaps
        if report.compliance_gaps:
            lines.extend([
                "## Compliance Gaps",
                "",
                "The following compliance requirements are not being met:",
                "",
            ])
            for gap in report.compliance_gaps:
                lines.append(f"- {gap}")
            lines.append("")

        # All recommendations
        if report.recommendations:
            lines.extend([
                "## All Recommendations",
                "",
            ])
            for priority in RecommendationPriority:
                recs = [r for r in report.recommendations if r.priority == priority]
                if not recs:
                    continue

                lines.append(f"### {priority.name} Priority")
                lines.append("")
                for rec in recs:
                    lines.append(f"- **{rec.title}** ({rec.effort} effort)")
                lines.append("")

        # Remediation plan summary
        if report.remediation_plan:
            plan = report.remediation_plan
            lines.extend([
                "## Remediation Plan Summary",
                "",
                f"- **Total Actions:** {len(plan.actions)}",
                f"- **Findings Addressed:** {plan.findings_addressed}",
                f"- **Total Effort:** {plan.total_effort_hours:.1f} hours",
                "",
            ])

        return "\n".join(lines)

    def quick_analyze(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Quick analysis returning essential info.

        Args:
            findings: Findings to analyze.

        Returns:
            Dictionary with key metrics and recommendations.
        """
        filtered = self._filter_findings(findings)
        recommendations = self.recommendation_engine.generate(
            filtered,
            max_per_category=2,
        )
        immediate = [r for r in recommendations if r.priority == RecommendationPriority.IMMEDIATE]

        return {
            "risk_score": self._calculate_risk_score(filtered),
            "total_findings": len(filtered),
            "immediate_actions_needed": len(immediate),
            "top_recommendations": [
                {"title": r.title, "priority": r.priority.name}
                for r in recommendations[:5]
            ],
            "compliance_gaps": self._identify_compliance_gaps(filtered)[:10],
        }
