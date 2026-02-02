"""Remediation planning and tracking.

Creates structured remediation plans from findings
and recommendations with prioritization and effort estimates.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from mass.core.findings import Finding
from mass.core.types import Severity
from mass.policy.recommendations import Recommendation, RecommendationPriority


class RemediationStatus(Enum):
    """Status of a remediation action."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    VERIFIED = "verified"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class RemediationAction:
    """A single remediation action to take."""

    id: str
    title: str
    description: str
    status: RemediationStatus = RemediationStatus.PENDING

    # What it addresses
    finding_ids: list[str] = field(default_factory=list)
    recommendation_id: str | None = None

    # Implementation details
    steps: list[str] = field(default_factory=list)
    code_changes: dict[str, str] = field(default_factory=dict)  # file -> change description
    config_changes: dict[str, Any] = field(default_factory=dict)

    # Priority and effort
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    effort_hours: float = 0.0
    requires_downtime: bool = False

    # Assignment and tracking
    assignee: str | None = None
    due_date: datetime | None = None
    completed_date: datetime | None = None
    notes: list[str] = field(default_factory=list)

    # Verification
    verification_steps: list[str] = field(default_factory=list)
    verified_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "finding_ids": self.finding_ids,
            "recommendation_id": self.recommendation_id,
            "steps": self.steps,
            "code_changes": self.code_changes,
            "config_changes": self.config_changes,
            "priority": self.priority.name.lower(),
            "effort_hours": self.effort_hours,
            "requires_downtime": self.requires_downtime,
            "assignee": self.assignee,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "completed_date": self.completed_date.isoformat() if self.completed_date else None,
            "notes": self.notes,
            "verification_steps": self.verification_steps,
            "verified_by": self.verified_by,
        }


@dataclass
class RemediationPlan:
    """A complete remediation plan for a scan."""

    id: str
    scan_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Actions
    actions: list[RemediationAction] = field(default_factory=list)

    # Summary
    total_findings: int = 0
    findings_addressed: int = 0
    total_effort_hours: float = 0.0

    # Status
    status: str = "draft"  # draft, approved, in_progress, completed

    # Metadata
    created_by: str | None = None
    approved_by: str | None = None
    notes: str = ""

    def add_action(self, action: RemediationAction) -> None:
        """Add an action to the plan."""
        self.actions.append(action)
        self.findings_addressed += len(action.finding_ids)
        self.total_effort_hours += action.effort_hours

    def get_by_priority(
        self,
        priority: RecommendationPriority,
    ) -> list[RemediationAction]:
        """Get actions by priority."""
        return [a for a in self.actions if a.priority == priority]

    def get_pending(self) -> list[RemediationAction]:
        """Get pending actions."""
        return [a for a in self.actions if a.status == RemediationStatus.PENDING]

    def get_in_progress(self) -> list[RemediationAction]:
        """Get in-progress actions."""
        return [a for a in self.actions if a.status == RemediationStatus.IN_PROGRESS]

    def get_completed(self) -> list[RemediationAction]:
        """Get completed actions."""
        return [
            a for a in self.actions
            if a.status in (RemediationStatus.COMPLETED, RemediationStatus.VERIFIED)
        ]

    def calculate_progress(self) -> float:
        """Calculate overall progress percentage."""
        if not self.actions:
            return 0.0

        completed = len(self.get_completed())
        return (completed / len(self.actions)) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat(),
            "actions": [a.to_dict() for a in self.actions],
            "total_findings": self.total_findings,
            "findings_addressed": self.findings_addressed,
            "total_effort_hours": self.total_effort_hours,
            "status": self.status,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "notes": self.notes,
            "progress_percent": self.calculate_progress(),
            "summary": {
                "pending": len(self.get_pending()),
                "in_progress": len(self.get_in_progress()),
                "completed": len(self.get_completed()),
            },
        }


class RemediationRegistry:
    """Registry of remediation patterns for common findings."""

    # Effort estimates by finding type (hours)
    EFFORT_ESTIMATES: dict[str, float] = {
        "prompt_injection": 8.0,
        "secret_exposure": 2.0,
        "pii_exposure": 4.0,
        "unsafe_model_format": 16.0,
        "privileged_container": 4.0,
        "missing_authentication": 8.0,
        "missing_rate_limit": 2.0,
        "hardcoded_credential": 1.0,
        "insecure_mcp_server": 4.0,
        "default": 4.0,
    }

    # Remediation templates
    TEMPLATES: dict[str, dict[str, Any]] = {
        "prompt_injection": {
            "title": "Fix Prompt Injection Vulnerability",
            "steps": [
                "Review affected code for injection points",
                "Implement input sanitization",
                "Add injection pattern detection",
                "Test with known injection attempts",
                "Deploy and monitor",
            ],
            "verification": [
                "Run injection test suite",
                "Verify sanitization is applied",
                "Check logs for blocked attempts",
            ],
        },
        "secret_exposure": {
            "title": "Remove Exposed Secrets",
            "steps": [
                "Identify all exposed secrets",
                "Rotate compromised credentials immediately",
                "Remove secrets from code/config",
                "Add to .gitignore",
                "Use secret manager",
            ],
            "verification": [
                "Run secret scanner",
                "Verify no secrets in repository",
                "Confirm secrets are rotated",
            ],
        },
        "unsafe_model_format": {
            "title": "Convert to Safe Model Format",
            "steps": [
                "Identify unsafe model files (pickle, pt, pth)",
                "Convert to safetensors or ONNX",
                "Test converted model functionality",
                "Update loading code",
                "Remove unsafe format files",
            ],
            "verification": [
                "Verify only safe formats exist",
                "Test model inference works",
                "Confirm loading rejects unsafe formats",
            ],
        },
        "privileged_container": {
            "title": "Remove Privileged Container Mode",
            "steps": [
                "Review why privileged mode was needed",
                "Identify minimum required capabilities",
                "Update container spec with capabilities",
                "Remove privileged flag",
                "Test functionality",
            ],
            "verification": [
                "Verify container runs without privileged",
                "Confirm required functionality works",
                "Check security context is correct",
            ],
        },
    }

    @classmethod
    def get_effort(cls, finding_type: str) -> float:
        """Get effort estimate for a finding type."""
        return cls.EFFORT_ESTIMATES.get(finding_type, cls.EFFORT_ESTIMATES["default"])

    @classmethod
    def get_template(cls, finding_type: str) -> dict[str, Any] | None:
        """Get remediation template for a finding type."""
        return cls.TEMPLATES.get(finding_type)


def create_remediation_plan(
    scan_id: str,
    findings: list[Finding],
    recommendations: list[Recommendation],
) -> RemediationPlan:
    """Create a remediation plan from findings and recommendations.

    Args:
        scan_id: ID of the scan.
        findings: List of findings.
        recommendations: List of recommendations.

    Returns:
        Complete remediation plan.
    """
    plan = RemediationPlan(
        id=str(uuid4()),
        scan_id=scan_id,
        total_findings=len(findings),
    )

    # Create actions from recommendations
    for rec in recommendations:
        # Estimate effort based on finding types
        effort = 0.0
        for finding_id in rec.addresses_findings:
            finding = next((f for f in findings if f.id == finding_id), None)
            if finding:
                effort += RemediationRegistry.get_effort(finding.category.value)

        action = RemediationAction(
            id=f"action-{uuid4().hex[:8]}",
            title=rec.title,
            description=rec.description,
            finding_ids=rec.addresses_findings,
            recommendation_id=rec.id,
            steps=rec.action_steps,
            priority=rec.priority,
            effort_hours=effort if effort > 0 else rec.estimated_hours or 4.0,
            requires_downtime=rec.requires_downtime,
            verification_steps=rec.verification_steps,
        )

        plan.add_action(action)

    return plan


def generate_remediation_report(plan: RemediationPlan) -> str:
    """Generate a human-readable remediation report.

    Args:
        plan: Remediation plan.

    Returns:
        Markdown formatted report.
    """
    lines = [
        f"# Remediation Plan: {plan.id}",
        "",
        f"**Scan ID:** {plan.scan_id}",
        f"**Created:** {plan.created_at.strftime('%Y-%m-%d %H:%M')}",
        f"**Status:** {plan.status}",
        "",
        "## Summary",
        "",
        f"- **Total Findings:** {plan.total_findings}",
        f"- **Findings Addressed:** {plan.findings_addressed}",
        f"- **Total Actions:** {len(plan.actions)}",
        f"- **Estimated Effort:** {plan.total_effort_hours:.1f} hours",
        f"- **Progress:** {plan.calculate_progress():.1f}%",
        "",
        "## Actions by Priority",
        "",
    ]

    # Group by priority
    for priority in RecommendationPriority:
        actions = plan.get_by_priority(priority)
        if not actions:
            continue

        lines.append(f"### {priority.name} Priority")
        lines.append("")

        for action in actions:
            status_emoji = {
                RemediationStatus.PENDING: "⏳",
                RemediationStatus.IN_PROGRESS: "🔄",
                RemediationStatus.COMPLETED: "✅",
                RemediationStatus.VERIFIED: "✓✓",
                RemediationStatus.BLOCKED: "🚫",
                RemediationStatus.ACCEPTED_RISK: "⚠️",
            }.get(action.status, "❓")

            lines.append(f"#### {status_emoji} {action.title}")
            lines.append("")
            lines.append(f"**Status:** {action.status.value}")
            lines.append(f"**Effort:** {action.effort_hours:.1f} hours")
            if action.assignee:
                lines.append(f"**Assignee:** {action.assignee}")
            lines.append("")
            lines.append(action.description)
            lines.append("")

            if action.steps:
                lines.append("**Steps:**")
                for i, step in enumerate(action.steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

        lines.append("")

    return "\n".join(lines)
