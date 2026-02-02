"""Recommendation engine for security findings.

Generates actionable recommendations based on findings,
prioritized by risk and effort.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from collections import defaultdict

from mass.core.findings import Finding
from mass.core.types import AttackCategory, Severity


class RecommendationType(Enum):
    """Types of recommendations."""

    FIX = "fix"  # Direct fix for the issue
    MITIGATE = "mitigate"  # Mitigation if fix not possible
    COMPENSATE = "compensate"  # Compensating control
    ACCEPT = "accept"  # Accept with documentation
    TRANSFER = "transfer"  # Transfer risk (insurance, etc.)


class RecommendationPriority(Enum):
    """Priority levels for recommendations."""

    IMMEDIATE = 1  # Fix now
    HIGH = 2  # Fix within days
    MEDIUM = 3  # Fix within weeks
    LOW = 4  # Fix when convenient
    INFORMATIONAL = 5  # No action required


@dataclass
class Recommendation:
    """A security recommendation."""

    id: str
    title: str
    description: str
    recommendation_type: RecommendationType
    priority: RecommendationPriority

    # Guidance
    action_steps: list[str] = field(default_factory=list)
    code_examples: dict[str, str] = field(default_factory=dict)
    configuration_changes: dict[str, Any] = field(default_factory=dict)

    # Impact
    addresses_findings: list[str] = field(default_factory=list)  # Finding IDs
    addresses_categories: list[AttackCategory] = field(default_factory=list)
    compliance_impact: list[str] = field(default_factory=list)

    # Effort
    effort: str = "medium"  # low, medium, high
    estimated_hours: float | None = None
    requires_downtime: bool = False

    # Success criteria
    success_criteria: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def priority_score(self) -> int:
        """Get numeric priority score for sorting."""
        return self.priority.value

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "type": self.recommendation_type.value,
            "priority": self.priority.name.lower(),
            "action_steps": self.action_steps,
            "code_examples": self.code_examples,
            "configuration_changes": self.configuration_changes,
            "addresses_findings": self.addresses_findings,
            "addresses_categories": [c.value for c in self.addresses_categories],
            "compliance_impact": self.compliance_impact,
            "effort": self.effort,
            "estimated_hours": self.estimated_hours,
            "requires_downtime": self.requires_downtime,
            "success_criteria": self.success_criteria,
            "verification_steps": self.verification_steps,
            "tags": self.tags,
            "references": self.references,
        }


class RecommendationEngine:
    """Generates recommendations from findings.

    Analyzes findings and generates prioritized recommendations
    for fixes, mitigations, and compensating controls.
    """

    # Category to recommendation mappings
    CATEGORY_RECOMMENDATIONS: dict[AttackCategory, list[dict[str, Any]]] = {
        AttackCategory.PROMPT_INJECTION: [
            {
                "id": "rec-pi-input-validation",
                "title": "Implement Prompt Input Validation",
                "description": "Add input validation to detect and block prompt injection attempts.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.IMMEDIATE,
                "effort": "medium",
                "steps": [
                    "Install an input validation library (e.g., rebuff, guardrails-ai)",
                    "Create validation rules for injection patterns",
                    "Wrap model inference calls with validation",
                    "Log and alert on blocked attempts",
                ],
                "success_criteria": [
                    "Input validation is applied to 100% of user inputs",
                    "Known injection patterns are blocked",
                    "Blocked attempts are logged",
                ],
            },
            {
                "id": "rec-pi-delimiter",
                "title": "Use Structured Prompts with Delimiters",
                "description": "Separate user content from system instructions using clear delimiters.",
                "type": RecommendationType.MITIGATE,
                "priority": RecommendationPriority.HIGH,
                "effort": "low",
                "steps": [
                    "Define clear delimiter patterns (e.g., XML tags, markers)",
                    "Wrap user content in delimiters in all prompts",
                    "Add instructions to model to respect delimiters",
                    "Test with common injection attempts",
                ],
            },
        ],
        AttackCategory.SENSITIVE_INFO: [
            {
                "id": "rec-si-output-filter",
                "title": "Implement Output Filtering for Sensitive Data",
                "description": "Filter model outputs to detect and redact sensitive information.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.IMMEDIATE,
                "effort": "medium",
                "steps": [
                    "Deploy PII detection on model outputs",
                    "Configure redaction rules for sensitive patterns",
                    "Test with sample sensitive data",
                    "Monitor redaction effectiveness",
                ],
            },
        ],
        AttackCategory.SECRETS_EXPOSURE: [
            {
                "id": "rec-se-secret-scan",
                "title": "Implement Secret Scanning",
                "description": "Scan code and outputs for exposed secrets and credentials.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.IMMEDIATE,
                "effort": "low",
                "steps": [
                    "Add pre-commit hooks for secret scanning",
                    "Scan model outputs for secret patterns",
                    "Rotate any exposed credentials immediately",
                    "Add secrets to .gitignore patterns",
                ],
            },
            {
                "id": "rec-se-secret-manager",
                "title": "Use Secret Manager",
                "description": "Move secrets to a dedicated secret management solution.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "medium",
                "steps": [
                    "Choose secret manager (Vault, AWS Secrets Manager, etc.)",
                    "Migrate secrets from code/config files",
                    "Update application to fetch secrets at runtime",
                    "Implement secret rotation",
                ],
            },
        ],
        AttackCategory.SUPPLY_CHAIN: [
            {
                "id": "rec-sc-verify-models",
                "title": "Verify Model Integrity",
                "description": "Implement verification for model files before loading.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.IMMEDIATE,
                "effort": "medium",
                "steps": [
                    "Generate SHA256 hashes for all model files",
                    "Store hashes in secure, tamper-proof storage",
                    "Verify hash before loading models",
                    "Alert on hash mismatches",
                ],
            },
            {
                "id": "rec-sc-safe-formats",
                "title": "Use Safe Model Formats",
                "description": "Convert models to safe serialization formats.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.IMMEDIATE,
                "effort": "high",
                "steps": [
                    "Identify all pickle/unsafe format models",
                    "Convert to safetensors or ONNX format",
                    "Verify converted models work correctly",
                    "Update loading code to reject unsafe formats",
                ],
            },
        ],
        AttackCategory.DATA_MODEL_POISONING: [
            {
                "id": "rec-dmp-data-validation",
                "title": "Implement Training Data Validation",
                "description": "Validate training data for integrity and potential poisoning.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "high",
                "steps": [
                    "Implement data quality checks",
                    "Scan for anomalous data points",
                    "Verify data provenance",
                    "Use data versioning",
                ],
            },
        ],
        AttackCategory.PRIVILEGE_ESCALATION: [
            {
                "id": "rec-pe-least-privilege",
                "title": "Implement Least Privilege Access",
                "description": "Reduce permissions to minimum necessary.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "medium",
                "steps": [
                    "Audit current permissions",
                    "Define minimum required permissions per role",
                    "Implement RBAC",
                    "Remove unnecessary permissions",
                ],
            },
        ],
        AttackCategory.EXCESSIVE_AGENCY: [
            {
                "id": "rec-ea-limit-actions",
                "title": "Limit Model Actions",
                "description": "Restrict what actions the model can perform autonomously.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "medium",
                "steps": [
                    "Define allowed action whitelist",
                    "Implement action filtering layer",
                    "Require human approval for sensitive actions",
                    "Log all action attempts",
                ],
            },
        ],
        AttackCategory.DENIAL_OF_SERVICE: [
            {
                "id": "rec-dos-rate-limit",
                "title": "Implement Rate Limiting",
                "description": "Add rate limiting to prevent resource exhaustion.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "low",
                "steps": [
                    "Configure per-user rate limits",
                    "Add global rate limits",
                    "Implement request queuing",
                    "Return 429 responses with retry-after",
                ],
            },
            {
                "id": "rec-dos-resource-quota",
                "title": "Set Resource Quotas",
                "description": "Limit compute resources per request.",
                "type": RecommendationType.MITIGATE,
                "priority": RecommendationPriority.HIGH,
                "effort": "low",
                "steps": [
                    "Set memory limits per container/process",
                    "Set CPU time limits",
                    "Limit output token count",
                    "Implement request timeouts",
                ],
            },
        ],
        AttackCategory.MODEL_THEFT: [
            {
                "id": "rec-mt-access-control",
                "title": "Restrict Model Access",
                "description": "Implement access controls on model endpoints and files.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "medium",
                "steps": [
                    "Require authentication for all inference endpoints",
                    "Restrict direct model file access",
                    "Implement API key or token-based access",
                    "Monitor for extraction attempts",
                ],
            },
        ],
        AttackCategory.JAILBREAK: [
            {
                "id": "rec-jb-content-filter",
                "title": "Implement Content Filtering",
                "description": "Filter outputs for jailbreak indicators and harmful content.",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "effort": "medium",
                "steps": [
                    "Deploy content classification on outputs",
                    "Define harmful content categories",
                    "Block or flag harmful outputs",
                    "Log jailbreak attempts",
                ],
            },
        ],
    }

    def __init__(self) -> None:
        """Initialize the recommendation engine."""
        self._custom_recommendations: dict[AttackCategory, list[dict]] = {}

    def add_custom_recommendation(
        self,
        category: AttackCategory,
        recommendation: dict[str, Any],
    ) -> None:
        """Add a custom recommendation for a category."""
        if category not in self._custom_recommendations:
            self._custom_recommendations[category] = []
        self._custom_recommendations[category].append(recommendation)

    def generate(
        self,
        findings: list[Finding],
        include_mitigations: bool = True,
        max_per_category: int = 3,
    ) -> list[Recommendation]:
        """Generate recommendations from findings.

        Args:
            findings: List of findings to analyze.
            include_mitigations: Include mitigation recommendations.
            max_per_category: Maximum recommendations per category.

        Returns:
            List of prioritized recommendations.
        """
        recommendations: list[Recommendation] = []
        seen_ids: set[str] = set()
        finding_ids_by_category: dict[AttackCategory, list[str]] = defaultdict(list)

        # Group findings by category
        for finding in findings:
            finding_ids_by_category[finding.category].append(finding.id)

        # Generate recommendations for each category
        for category, finding_ids in finding_ids_by_category.items():
            # Get recommendations for this category
            category_recs = self.CATEGORY_RECOMMENDATIONS.get(category, [])
            custom_recs = self._custom_recommendations.get(category, [])
            all_recs = category_recs + custom_recs

            count = 0
            for rec_data in all_recs:
                if count >= max_per_category:
                    break

                # Skip if not including mitigations
                rec_type = rec_data.get("type", RecommendationType.FIX)
                if not include_mitigations and rec_type != RecommendationType.FIX:
                    continue

                # Skip duplicates
                rec_id = rec_data.get("id", "")
                if rec_id in seen_ids:
                    continue
                seen_ids.add(rec_id)

                # Create recommendation
                rec = Recommendation(
                    id=rec_id,
                    title=rec_data.get("title", ""),
                    description=rec_data.get("description", ""),
                    recommendation_type=rec_type,
                    priority=rec_data.get("priority", RecommendationPriority.MEDIUM),
                    action_steps=rec_data.get("steps", []),
                    code_examples=rec_data.get("code_examples", {}),
                    addresses_findings=finding_ids,
                    addresses_categories=[category],
                    effort=rec_data.get("effort", "medium"),
                    success_criteria=rec_data.get("success_criteria", []),
                    tags=rec_data.get("tags", []),
                    references=rec_data.get("references", []),
                )
                recommendations.append(rec)
                count += 1

        # Add severity-based priority adjustment
        for rec in recommendations:
            self._adjust_priority_by_findings(rec, findings)

        # Sort by priority
        recommendations.sort(key=lambda r: r.priority_score)

        return recommendations

    def _adjust_priority_by_findings(
        self,
        rec: Recommendation,
        findings: list[Finding],
    ) -> None:
        """Adjust recommendation priority based on finding severity."""
        relevant_findings = [
            f for f in findings if f.id in rec.addresses_findings
        ]

        if not relevant_findings:
            return

        # Check for critical findings
        has_critical = any(f.severity == Severity.CRITICAL for f in relevant_findings)
        has_high = any(f.severity == Severity.HIGH for f in relevant_findings)

        if has_critical and rec.priority.value > RecommendationPriority.IMMEDIATE.value:
            rec.priority = RecommendationPriority.IMMEDIATE
        elif has_high and rec.priority.value > RecommendationPriority.HIGH.value:
            rec.priority = RecommendationPriority.HIGH

    def generate_summary(
        self,
        recommendations: list[Recommendation],
    ) -> dict[str, Any]:
        """Generate a summary of recommendations.

        Args:
            recommendations: List of recommendations.

        Returns:
            Summary dictionary.
        """
        by_priority: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)
        by_effort: dict[str, int] = defaultdict(int)

        for rec in recommendations:
            by_priority[rec.priority.name.lower()] += 1
            by_type[rec.recommendation_type.value] += 1
            by_effort[rec.effort] += 1

        return {
            "total": len(recommendations),
            "by_priority": dict(by_priority),
            "by_type": dict(by_type),
            "by_effort": dict(by_effort),
            "immediate_actions": len([
                r for r in recommendations
                if r.priority == RecommendationPriority.IMMEDIATE
            ]),
        }
