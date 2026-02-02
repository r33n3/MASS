"""Tests for policy and guardrail recommendation engine."""

import pytest
from datetime import datetime
from uuid import uuid4

from mass.core.types import AttackCategory, Severity
from mass.core.findings import Finding
from mass.policy.guardrails import (
    Guardrail,
    GuardrailType,
    GuardrailSeverity,
    GuardrailRegistry,
    get_default_guardrails,
)
from mass.policy.templates import (
    PolicyTemplate,
    PolicyRule,
    PolicyCategory,
    PolicyRegistry,
    get_policy_templates,
)
from mass.policy.recommendations import (
    Recommendation,
    RecommendationType,
    RecommendationPriority,
    RecommendationEngine,
)
from mass.policy.remediation import (
    RemediationAction,
    RemediationPlan,
    RemediationStatus,
    RemediationRegistry,
    create_remediation_plan,
    generate_remediation_report,
)
from mass.policy.engine import (
    PolicyEngine,
    PolicyEngineConfig,
    PolicyReport,
    GuardrailViolation,
)
from mass.core.types import ComponentType


# =============================================================================
# Guardrails Tests
# =============================================================================

class TestGuardrail:
    """Tests for Guardrail dataclass."""

    def test_guardrail_creation(self):
        """Test creating a guardrail."""
        guardrail = Guardrail(
            id="test-guard",
            name="Test Guardrail",
            description="A test guardrail",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
        )
        assert guardrail.id == "test-guard"
        assert guardrail.name == "Test Guardrail"
        assert guardrail.guardrail_type == GuardrailType.INPUT_VALIDATION
        assert guardrail.severity == GuardrailSeverity.HIGH

    def test_guardrail_with_mitigation_categories(self):
        """Test guardrail with mitigation categories."""
        guardrail = Guardrail(
            id="test-guard",
            name="Test Guardrail",
            description="A test guardrail",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.CRITICAL,
            mitigates_categories=[
                AttackCategory.PROMPT_INJECTION,
                AttackCategory.JAILBREAK,
            ],
        )
        assert len(guardrail.mitigates_categories) == 2
        assert AttackCategory.PROMPT_INJECTION in guardrail.mitigates_categories

    def test_guardrail_to_dict(self):
        """Test guardrail serialization."""
        guardrail = Guardrail(
            id="test-guard",
            name="Test Guardrail",
            description="A test",
            guardrail_type=GuardrailType.OUTPUT_FILTERING,
            severity=GuardrailSeverity.MEDIUM,
            implementation_steps=["Step 1", "Step 2"],
            effort="low",
            effectiveness="high",
        )
        result = guardrail.to_dict()
        assert result["id"] == "test-guard"
        assert result["type"] == "output_filtering"
        assert result["severity"] == "medium"
        assert result["implementation_steps"] == ["Step 1", "Step 2"]
        assert result["effort"] == "low"


class TestGuardrailRegistry:
    """Tests for GuardrailRegistry."""

    def test_register_and_get(self):
        """Test registering and retrieving guardrails."""
        registry = GuardrailRegistry()
        guardrail = Guardrail(
            id="test-1",
            name="Test",
            description="Test",
            guardrail_type=GuardrailType.RATE_LIMITING,
            severity=GuardrailSeverity.HIGH,
        )
        registry.register(guardrail)

        retrieved = registry.get("test-1")
        assert retrieved is not None
        assert retrieved.id == "test-1"

    def test_get_nonexistent(self):
        """Test getting nonexistent guardrail."""
        registry = GuardrailRegistry()
        assert registry.get("nonexistent") is None

    def test_get_by_type(self):
        """Test getting guardrails by type."""
        registry = GuardrailRegistry()
        registry.register(Guardrail(
            id="test-1",
            name="Test 1",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
        ))
        registry.register(Guardrail(
            id="test-2",
            name="Test 2",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.MEDIUM,
        ))
        registry.register(Guardrail(
            id="test-3",
            name="Test 3",
            description="Test",
            guardrail_type=GuardrailType.OUTPUT_FILTERING,
            severity=GuardrailSeverity.LOW,
        ))

        input_guards = registry.get_by_type(GuardrailType.INPUT_VALIDATION)
        assert len(input_guards) == 2

        output_guards = registry.get_by_type(GuardrailType.OUTPUT_FILTERING)
        assert len(output_guards) == 1

    def test_get_for_category(self):
        """Test getting guardrails for attack category."""
        registry = GuardrailRegistry()
        registry.register(Guardrail(
            id="test-1",
            name="Test 1",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
            mitigates_categories=[AttackCategory.PROMPT_INJECTION],
        ))
        registry.register(Guardrail(
            id="test-2",
            name="Test 2",
            description="Test",
            guardrail_type=GuardrailType.OUTPUT_FILTERING,
            severity=GuardrailSeverity.HIGH,
            mitigates_categories=[AttackCategory.DATA_LEAKAGE],
        ))

        pi_guards = registry.get_for_category(AttackCategory.PROMPT_INJECTION)
        assert len(pi_guards) == 1
        assert pi_guards[0].id == "test-1"

    def test_get_all(self):
        """Test getting all guardrails."""
        registry = GuardrailRegistry()
        registry.register(Guardrail(
            id="test-1",
            name="Test 1",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
        ))
        registry.register(Guardrail(
            id="test-2",
            name="Test 2",
            description="Test",
            guardrail_type=GuardrailType.OUTPUT_FILTERING,
            severity=GuardrailSeverity.MEDIUM,
        ))

        all_guards = registry.get_all()
        assert len(all_guards) == 2

    def test_get_by_severity(self):
        """Test getting guardrails by severity."""
        registry = GuardrailRegistry()
        registry.register(Guardrail(
            id="test-1",
            name="Test 1",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.CRITICAL,
        ))
        registry.register(Guardrail(
            id="test-2",
            name="Test 2",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
        ))

        critical = registry.get_by_severity(GuardrailSeverity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].id == "test-1"


class TestDefaultGuardrails:
    """Tests for default guardrails."""

    def test_get_default_guardrails(self):
        """Test getting default guardrails registry."""
        registry = get_default_guardrails()
        all_guards = registry.get_all()
        assert len(all_guards) >= 10  # Should have multiple default guardrails

    def test_prompt_sanitization_guardrail_exists(self):
        """Test that prompt sanitization guardrail exists."""
        registry = get_default_guardrails()
        guardrail = registry.get("grd-input-sanitize")
        assert guardrail is not None
        assert guardrail.severity == GuardrailSeverity.CRITICAL

    def test_pii_output_filtering_exists(self):
        """Test that PII output filtering exists."""
        registry = get_default_guardrails()
        guardrail = registry.get("grd-output-pii")
        assert guardrail is not None
        assert guardrail.guardrail_type == GuardrailType.OUTPUT_FILTERING

    def test_guardrails_have_implementation_steps(self):
        """Test that guardrails have implementation steps."""
        registry = get_default_guardrails()
        guardrail = registry.get("grd-input-sanitize")
        assert guardrail is not None
        assert len(guardrail.implementation_steps) > 0


# =============================================================================
# Policy Templates Tests
# =============================================================================

class TestPolicyRule:
    """Tests for PolicyRule dataclass."""

    def test_policy_rule_creation(self):
        """Test creating a policy rule."""
        rule = PolicyRule(
            id="rule-1",
            name="Test Rule",
            description="A test rule",
            condition="When X happens",
            action="Do Y",
            severity=Severity.HIGH,
        )
        assert rule.id == "rule-1"
        assert rule.severity == Severity.HIGH
        assert rule.enabled is True

    def test_policy_rule_to_dict(self):
        """Test policy rule serialization."""
        rule = PolicyRule(
            id="rule-1",
            name="Test Rule",
            description="A test rule",
            condition="When X happens",
            action="Do Y",
            severity=Severity.CRITICAL,
            enabled=False,
        )
        result = rule.to_dict()
        assert result["id"] == "rule-1"
        assert result["severity"] == "critical"
        assert result["enabled"] is False


class TestPolicyTemplate:
    """Tests for PolicyTemplate dataclass."""

    def test_policy_template_creation(self):
        """Test creating a policy template."""
        template = PolicyTemplate(
            id="pol-1",
            name="Test Policy",
            description="A test policy",
            category=PolicyCategory.PROMPT_SECURITY,
        )
        assert template.id == "pol-1"
        assert template.category == PolicyCategory.PROMPT_SECURITY
        assert template.version == "1.0.0"

    def test_policy_template_with_rules(self):
        """Test policy template with rules."""
        rules = [
            PolicyRule(
                id="rule-1",
                name="Rule 1",
                description="First rule",
                condition="Condition 1",
                action="Action 1",
            ),
            PolicyRule(
                id="rule-2",
                name="Rule 2",
                description="Second rule",
                condition="Condition 2",
                action="Action 2",
            ),
        ]
        template = PolicyTemplate(
            id="pol-1",
            name="Test Policy",
            description="A test policy",
            category=PolicyCategory.DATA_PROTECTION,
            rules=rules,
        )
        assert len(template.rules) == 2

    def test_policy_template_to_dict(self):
        """Test policy template serialization."""
        template = PolicyTemplate(
            id="pol-1",
            name="Test Policy",
            description="A test policy",
            category=PolicyCategory.ACCESS_CONTROL,
            compliance_frameworks=["soc2", "gdpr"],
            mitigates=[AttackCategory.PRIVILEGE_ESCALATION],
        )
        result = template.to_dict()
        assert result["id"] == "pol-1"
        assert result["category"] == "access_control"
        assert "soc2" in result["compliance_frameworks"]
        assert "privilege_escalation" in result["mitigates"]


class TestPolicyRegistry:
    """Tests for PolicyRegistry."""

    def test_register_and_get(self):
        """Test registering and retrieving templates."""
        registry = PolicyRegistry()
        template = PolicyTemplate(
            id="pol-1",
            name="Test",
            description="Test",
            category=PolicyCategory.MONITORING,
        )
        registry.register(template)

        retrieved = registry.get("pol-1")
        assert retrieved is not None
        assert retrieved.id == "pol-1"

    def test_get_by_category(self):
        """Test getting templates by category."""
        registry = PolicyRegistry()
        registry.register(PolicyTemplate(
            id="pol-1",
            name="Test 1",
            description="Test",
            category=PolicyCategory.MONITORING,
        ))
        registry.register(PolicyTemplate(
            id="pol-2",
            name="Test 2",
            description="Test",
            category=PolicyCategory.MONITORING,
        ))
        registry.register(PolicyTemplate(
            id="pol-3",
            name="Test 3",
            description="Test",
            category=PolicyCategory.COMPLIANCE,
        ))

        monitoring = registry.get_by_category(PolicyCategory.MONITORING)
        assert len(monitoring) == 2

    def test_get_for_compliance(self):
        """Test getting templates for compliance framework."""
        registry = PolicyRegistry()
        registry.register(PolicyTemplate(
            id="pol-1",
            name="Test 1",
            description="Test",
            category=PolicyCategory.DATA_PROTECTION,
            compliance_frameworks=["gdpr", "soc2"],
        ))
        registry.register(PolicyTemplate(
            id="pol-2",
            name="Test 2",
            description="Test",
            category=PolicyCategory.ACCESS_CONTROL,
            compliance_frameworks=["soc2"],
        ))

        gdpr_policies = registry.get_for_compliance("gdpr")
        assert len(gdpr_policies) == 1
        assert gdpr_policies[0].id == "pol-1"

        soc2_policies = registry.get_for_compliance("soc2")
        assert len(soc2_policies) == 2


class TestDefaultPolicyTemplates:
    """Tests for default policy templates."""

    def test_get_policy_templates(self):
        """Test getting default policy templates."""
        registry = get_policy_templates()
        all_templates = registry.get_all()
        assert len(all_templates) >= 5

    def test_prompt_injection_defense_exists(self):
        """Test that prompt injection defense policy exists."""
        registry = get_policy_templates()
        policy = registry.get("pol-prompt-injection-defense")
        assert policy is not None
        assert len(policy.rules) > 0

    def test_data_loss_prevention_exists(self):
        """Test that DLP policy exists."""
        registry = get_policy_templates()
        policy = registry.get("pol-data-loss-prevention")
        assert policy is not None
        assert AttackCategory.DATA_LEAKAGE in policy.mitigates


# =============================================================================
# Recommendations Tests
# =============================================================================

class TestRecommendation:
    """Tests for Recommendation dataclass."""

    def test_recommendation_creation(self):
        """Test creating a recommendation."""
        rec = Recommendation(
            id="rec-1",
            title="Test Recommendation",
            description="A test recommendation",
            recommendation_type=RecommendationType.FIX,
            priority=RecommendationPriority.HIGH,
        )
        assert rec.id == "rec-1"
        assert rec.recommendation_type == RecommendationType.FIX
        assert rec.priority == RecommendationPriority.HIGH

    def test_recommendation_priority_score(self):
        """Test priority score property."""
        rec_immediate = Recommendation(
            id="rec-1",
            title="Test",
            description="Test",
            recommendation_type=RecommendationType.FIX,
            priority=RecommendationPriority.IMMEDIATE,
        )
        rec_low = Recommendation(
            id="rec-2",
            title="Test",
            description="Test",
            recommendation_type=RecommendationType.FIX,
            priority=RecommendationPriority.LOW,
        )

        assert rec_immediate.priority_score < rec_low.priority_score

    def test_recommendation_to_dict(self):
        """Test recommendation serialization."""
        rec = Recommendation(
            id="rec-1",
            title="Test Recommendation",
            description="A test",
            recommendation_type=RecommendationType.MITIGATE,
            priority=RecommendationPriority.MEDIUM,
            action_steps=["Step 1", "Step 2"],
            effort="low",
            estimated_hours=4.0,
        )
        result = rec.to_dict()
        assert result["id"] == "rec-1"
        assert result["type"] == "mitigate"
        assert result["priority"] == "medium"
        assert result["estimated_hours"] == 4.0


def create_test_finding(
    finding_id: str,
    category: AttackCategory,
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Helper to create test findings."""
    return Finding(
        id=finding_id,
        title="Test Finding",
        description="A test finding",
        category=category,
        severity=severity,
        component_type=ComponentType.MODEL,
        component_name="test-model",
        file_path="test.py",
    )


class TestRecommendationEngine:
    """Tests for RecommendationEngine."""

    def test_generate_recommendations(self):
        """Test generating recommendations."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]

        recs = engine.generate(findings)
        assert len(recs) > 0
        assert any(r.addresses_categories[0] == AttackCategory.PROMPT_INJECTION for r in recs)

    def test_generate_recommendations_multiple_categories(self):
        """Test generating recommendations for multiple categories."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION),
            create_test_finding("f2", AttackCategory.SECRETS_EXPOSURE),
            create_test_finding("f3", AttackCategory.DENIAL_OF_SERVICE),
        ]

        recs = engine.generate(findings)
        categories = {r.addresses_categories[0] for r in recs}
        assert AttackCategory.PROMPT_INJECTION in categories
        assert AttackCategory.SECRETS_EXPOSURE in categories

    def test_max_per_category(self):
        """Test max recommendations per category."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.SECRETS_EXPOSURE),
        ]

        recs = engine.generate(findings, max_per_category=1)
        secrets_recs = [r for r in recs if AttackCategory.SECRETS_EXPOSURE in r.addresses_categories]
        assert len(secrets_recs) <= 1

    def test_include_mitigations_false(self):
        """Test excluding mitigation recommendations."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION),
        ]

        recs = engine.generate(findings, include_mitigations=False)
        # Should only include FIX type recommendations
        for rec in recs:
            assert rec.recommendation_type == RecommendationType.FIX

    def test_priority_adjustment_critical_findings(self):
        """Test priority adjustment for critical findings."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.SECRETS_EXPOSURE, Severity.CRITICAL),
        ]

        recs = engine.generate(findings)
        # At least one should be IMMEDIATE due to critical finding
        immediate_recs = [r for r in recs if r.priority == RecommendationPriority.IMMEDIATE]
        assert len(immediate_recs) > 0

    def test_add_custom_recommendation(self):
        """Test adding custom recommendations."""
        engine = RecommendationEngine()
        engine.add_custom_recommendation(
            AttackCategory.PROMPT_INJECTION,
            {
                "id": "custom-rec",
                "title": "Custom Recommendation",
                "description": "A custom rec",
                "type": RecommendationType.FIX,
                "priority": RecommendationPriority.HIGH,
                "steps": ["Custom step"],
            }
        )

        findings = [create_test_finding("f1", AttackCategory.PROMPT_INJECTION)]
        recs = engine.generate(findings)

        custom = [r for r in recs if r.id == "custom-rec"]
        assert len(custom) == 1

    def test_generate_summary(self):
        """Test generating recommendation summary."""
        engine = RecommendationEngine()
        recs = [
            Recommendation(
                id="rec-1",
                title="Test 1",
                description="Test",
                recommendation_type=RecommendationType.FIX,
                priority=RecommendationPriority.IMMEDIATE,
                effort="low",
            ),
            Recommendation(
                id="rec-2",
                title="Test 2",
                description="Test",
                recommendation_type=RecommendationType.MITIGATE,
                priority=RecommendationPriority.HIGH,
                effort="medium",
            ),
        ]

        summary = engine.generate_summary(recs)
        assert summary["total"] == 2
        assert summary["immediate_actions"] == 1
        assert "fix" in summary["by_type"]

    def test_findings_addresses_tracking(self):
        """Test that recommendations track which findings they address."""
        engine = RecommendationEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION),
            create_test_finding("f2", AttackCategory.PROMPT_INJECTION),
        ]

        recs = engine.generate(findings)
        pi_recs = [r for r in recs if AttackCategory.PROMPT_INJECTION in r.addresses_categories]

        # Should address both findings
        if pi_recs:
            assert "f1" in pi_recs[0].addresses_findings
            assert "f2" in pi_recs[0].addresses_findings


# =============================================================================
# Remediation Tests
# =============================================================================

class TestRemediationAction:
    """Tests for RemediationAction dataclass."""

    def test_remediation_action_creation(self):
        """Test creating a remediation action."""
        action = RemediationAction(
            id="action-1",
            title="Fix the issue",
            description="Description",
        )
        assert action.id == "action-1"
        assert action.status == RemediationStatus.PENDING
        assert action.priority == RecommendationPriority.MEDIUM

    def test_remediation_action_to_dict(self):
        """Test remediation action serialization."""
        action = RemediationAction(
            id="action-1",
            title="Fix",
            description="Description",
            status=RemediationStatus.IN_PROGRESS,
            effort_hours=8.0,
            assignee="dev@example.com",
        )
        result = action.to_dict()
        assert result["id"] == "action-1"
        assert result["status"] == "in_progress"
        assert result["effort_hours"] == 8.0
        assert result["assignee"] == "dev@example.com"


class TestRemediationPlan:
    """Tests for RemediationPlan dataclass."""

    def test_remediation_plan_creation(self):
        """Test creating a remediation plan."""
        plan = RemediationPlan(
            id="plan-1",
            scan_id="scan-123",
        )
        assert plan.id == "plan-1"
        assert plan.status == "draft"
        assert plan.total_effort_hours == 0.0

    def test_add_action(self):
        """Test adding actions to plan."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        action = RemediationAction(
            id="action-1",
            title="Fix",
            description="Description",
            effort_hours=4.0,
            finding_ids=["f1", "f2"],
        )

        plan.add_action(action)

        assert len(plan.actions) == 1
        assert plan.findings_addressed == 2
        assert plan.total_effort_hours == 4.0

    def test_get_by_priority(self):
        """Test getting actions by priority."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        plan.add_action(RemediationAction(
            id="a1",
            title="High",
            description="High priority",
            priority=RecommendationPriority.HIGH,
        ))
        plan.add_action(RemediationAction(
            id="a2",
            title="Low",
            description="Low priority",
            priority=RecommendationPriority.LOW,
        ))

        high_actions = plan.get_by_priority(RecommendationPriority.HIGH)
        assert len(high_actions) == 1
        assert high_actions[0].id == "a1"

    def test_get_pending(self):
        """Test getting pending actions."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        plan.actions = [
            RemediationAction(id="a1", title="Pending", description="", status=RemediationStatus.PENDING),
            RemediationAction(id="a2", title="Done", description="", status=RemediationStatus.COMPLETED),
        ]

        pending = plan.get_pending()
        assert len(pending) == 1
        assert pending[0].id == "a1"

    def test_get_completed(self):
        """Test getting completed actions."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        plan.actions = [
            RemediationAction(id="a1", title="Pending", description="", status=RemediationStatus.PENDING),
            RemediationAction(id="a2", title="Done", description="", status=RemediationStatus.COMPLETED),
            RemediationAction(id="a3", title="Verified", description="", status=RemediationStatus.VERIFIED),
        ]

        completed = plan.get_completed()
        assert len(completed) == 2

    def test_calculate_progress(self):
        """Test calculating progress."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        plan.actions = [
            RemediationAction(id="a1", title="", description="", status=RemediationStatus.PENDING),
            RemediationAction(id="a2", title="", description="", status=RemediationStatus.COMPLETED),
            RemediationAction(id="a3", title="", description="", status=RemediationStatus.COMPLETED),
            RemediationAction(id="a4", title="", description="", status=RemediationStatus.IN_PROGRESS),
        ]

        progress = plan.calculate_progress()
        assert progress == 50.0  # 2 completed out of 4

    def test_calculate_progress_empty(self):
        """Test calculating progress with no actions."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123")
        assert plan.calculate_progress() == 0.0

    def test_to_dict(self):
        """Test plan serialization."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123", status="approved")
        plan.add_action(RemediationAction(
            id="a1",
            title="Action",
            description="Description",
            effort_hours=4.0,
        ))

        result = plan.to_dict()
        assert result["id"] == "plan-1"
        assert result["scan_id"] == "scan-123"
        assert result["status"] == "approved"
        assert len(result["actions"]) == 1
        assert "summary" in result


class TestRemediationRegistry:
    """Tests for RemediationRegistry."""

    def test_get_effort(self):
        """Test getting effort estimates."""
        effort = RemediationRegistry.get_effort("prompt_injection")
        assert effort == 8.0

    def test_get_effort_default(self):
        """Test getting default effort for unknown type."""
        effort = RemediationRegistry.get_effort("unknown_type")
        assert effort == 4.0  # Default value

    def test_get_template(self):
        """Test getting remediation template."""
        template = RemediationRegistry.get_template("secret_exposure")
        assert template is not None
        assert "title" in template
        assert "steps" in template

    def test_get_template_nonexistent(self):
        """Test getting nonexistent template."""
        template = RemediationRegistry.get_template("nonexistent")
        assert template is None


class TestCreateRemediationPlan:
    """Tests for create_remediation_plan function."""

    def test_create_remediation_plan(self):
        """Test creating a remediation plan."""
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]
        recommendations = [
            Recommendation(
                id="rec-1",
                title="Fix injection",
                description="Fix the injection issue",
                recommendation_type=RecommendationType.FIX,
                priority=RecommendationPriority.IMMEDIATE,
                action_steps=["Step 1", "Step 2"],
                addresses_findings=["f1"],
            ),
        ]

        plan = create_remediation_plan("scan-123", findings, recommendations)

        assert plan.scan_id == "scan-123"
        assert plan.total_findings == 1
        assert len(plan.actions) == 1
        assert plan.actions[0].title == "Fix injection"

    def test_create_remediation_plan_effort_estimate(self):
        """Test effort estimation in remediation plan."""
        findings = [
            create_test_finding("f1", AttackCategory.SECRETS_EXPOSURE, Severity.CRITICAL),
        ]
        recommendations = [
            Recommendation(
                id="rec-1",
                title="Remove secrets",
                description="Remove exposed secrets",
                recommendation_type=RecommendationType.FIX,
                priority=RecommendationPriority.IMMEDIATE,
                addresses_findings=["f1"],
            ),
        ]

        plan = create_remediation_plan("scan-123", findings, recommendations)

        # Should have effort based on secrets_exposure category
        assert plan.total_effort_hours > 0


class TestGenerateRemediationReport:
    """Tests for generate_remediation_report function."""

    def test_generate_report(self):
        """Test generating remediation report."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123", total_findings=5)
        plan.add_action(RemediationAction(
            id="a1",
            title="Fix Issue",
            description="Fix the security issue",
            priority=RecommendationPriority.IMMEDIATE,
            effort_hours=4.0,
            steps=["Do step 1", "Do step 2"],
        ))

        report = generate_remediation_report(plan)

        assert "# Remediation Plan" in report
        assert "scan-123" in report
        assert "Fix Issue" in report
        assert "4.0 hours" in report

    def test_report_includes_summary(self):
        """Test that report includes summary section."""
        plan = RemediationPlan(id="plan-1", scan_id="scan-123", total_findings=3)
        report = generate_remediation_report(plan)

        assert "## Summary" in report
        assert "Total Findings:" in report


# =============================================================================
# Policy Engine Tests
# =============================================================================

class TestPolicyEngineConfig:
    """Tests for PolicyEngineConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = PolicyEngineConfig()
        assert config.include_guardrails is True
        assert config.include_recommendations is True
        assert config.min_severity == Severity.LOW
        assert config.max_recommendations_per_category == 3

    def test_custom_config(self):
        """Test custom configuration."""
        config = PolicyEngineConfig(
            include_guardrails=False,
            min_severity=Severity.HIGH,
            max_recommendations_per_category=5,
        )
        assert config.include_guardrails is False
        assert config.min_severity == Severity.HIGH
        assert config.max_recommendations_per_category == 5


class TestGuardrailViolation:
    """Tests for GuardrailViolation."""

    def test_guardrail_violation_creation(self):
        """Test creating guardrail violation."""
        guardrail = Guardrail(
            id="g1",
            name="Test",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.HIGH,
        )
        violation = GuardrailViolation(
            guardrail=guardrail,
            related_findings=[create_test_finding("f1", AttackCategory.PROMPT_INJECTION)],
            priority="high",
        )

        assert violation.guardrail.id == "g1"
        assert len(violation.related_findings) == 1
        assert violation.priority == "high"

    def test_guardrail_violation_to_dict(self):
        """Test violation serialization."""
        guardrail = Guardrail(
            id="g1",
            name="Test",
            description="Test",
            guardrail_type=GuardrailType.INPUT_VALIDATION,
            severity=GuardrailSeverity.CRITICAL,
        )
        finding = create_test_finding("f1", AttackCategory.PROMPT_INJECTION)
        violation = GuardrailViolation(
            guardrail=guardrail,
            related_findings=[finding],
        )

        result = violation.to_dict()
        assert "guardrail" in result
        assert "f1" in result["related_findings"]


class TestPolicyReport:
    """Tests for PolicyReport."""

    def test_policy_report_creation(self):
        """Test creating policy report."""
        report = PolicyReport(scan_id="scan-123")
        assert report.scan_id == "scan-123"
        assert report.total_findings == 0
        assert report.risk_score == 0.0

    def test_policy_report_to_dict(self):
        """Test report serialization."""
        report = PolicyReport(
            scan_id="scan-123",
            total_findings=5,
            risk_score=75.0,
        )

        result = report.to_dict()
        assert result["scan_id"] == "scan-123"
        assert result["total_findings"] == 5
        assert result["risk_score"] == 75.0
        assert "generated_at" in result


class TestPolicyEngine:
    """Tests for PolicyEngine."""

    def test_engine_creation(self):
        """Test creating policy engine."""
        engine = PolicyEngine()
        assert engine.config is not None
        assert engine.guardrails is not None
        assert engine.policies is not None

    def test_engine_with_custom_config(self):
        """Test engine with custom config."""
        config = PolicyEngineConfig(include_guardrails=False)
        engine = PolicyEngine(config=config)
        assert engine.config.include_guardrails is False

    def test_analyze_empty_findings(self):
        """Test analyzing empty findings list."""
        engine = PolicyEngine()
        report = engine.analyze("scan-123", [])

        assert report.scan_id == "scan-123"
        assert report.total_findings == 0
        assert report.risk_score == 0.0

    def test_analyze_with_findings(self):
        """Test analyzing findings."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
            create_test_finding("f2", AttackCategory.SECRETS_EXPOSURE, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert report.total_findings == 2
        assert report.risk_score > 0
        assert len(report.recommendations) > 0

    def test_analyze_generates_guardrails(self):
        """Test that analysis generates guardrail violations."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert len(report.required_guardrails) > 0

    def test_analyze_generates_recommendations(self):
        """Test that analysis generates recommendations."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.DENIAL_OF_SERVICE, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert len(report.recommendations) > 0

    def test_analyze_generates_remediation_plan(self):
        """Test that analysis generates remediation plan."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]

        report = engine.analyze("scan-123", findings)

        assert report.remediation_plan is not None
        assert len(report.remediation_plan.actions) > 0

    def test_analyze_generates_markdown_report(self):
        """Test that analysis generates markdown report."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]

        report = engine.analyze("scan-123", findings)

        assert len(report.markdown_report) > 0
        assert "# MASS Policy" in report.markdown_report
        assert "Risk Score" in report.markdown_report

    def test_analyze_filters_by_severity(self):
        """Test that analysis filters by minimum severity."""
        config = PolicyEngineConfig(min_severity=Severity.HIGH)
        engine = PolicyEngine(config=config)
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
            create_test_finding("f2", AttackCategory.SECRETS_EXPOSURE, Severity.LOW),
            create_test_finding("f3", AttackCategory.DATA_LEAKAGE, Severity.INFO),
        ]

        report = engine.analyze("scan-123", findings)

        # Should only include CRITICAL finding (HIGH and above)
        assert report.total_findings == 1

    def test_analyze_counts_by_severity(self):
        """Test severity counting."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
            create_test_finding("f2", AttackCategory.SECRETS_EXPOSURE, Severity.CRITICAL),
            create_test_finding("f3", AttackCategory.DATA_LEAKAGE, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert report.findings_by_severity.get("critical") == 2
        assert report.findings_by_severity.get("high") == 1

    def test_analyze_counts_by_category(self):
        """Test category counting."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
            create_test_finding("f2", AttackCategory.PROMPT_INJECTION, Severity.MEDIUM),
            create_test_finding("f3", AttackCategory.SECRETS_EXPOSURE, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert report.findings_by_category.get("prompt_injection") == 2
        assert report.findings_by_category.get("secrets_exposure") == 1

    def test_analyze_immediate_actions(self):
        """Test immediate actions identification."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]

        report = engine.analyze("scan-123", findings)

        # Should have immediate actions for critical finding
        assert len(report.immediate_actions) > 0

    def test_analyze_risk_score_calculation(self):
        """Test risk score calculation."""
        engine = PolicyEngine()

        # Critical finding should have higher risk
        critical_findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]
        critical_report = engine.analyze("scan-1", critical_findings)

        # Low findings should have lower risk
        low_findings = [
            create_test_finding("f2", AttackCategory.PROMPT_INJECTION, Severity.LOW),
        ]
        low_report = engine.analyze("scan-2", low_findings)

        assert critical_report.risk_score > low_report.risk_score

    def test_analyze_without_guardrails(self):
        """Test analysis without guardrails."""
        config = PolicyEngineConfig(include_guardrails=False)
        engine = PolicyEngine(config=config)
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert len(report.required_guardrails) == 0
        assert len(report.guardrail_violations) == 0

    def test_analyze_without_recommendations(self):
        """Test analysis without recommendations."""
        config = PolicyEngineConfig(include_recommendations=False)
        engine = PolicyEngine(config=config)
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert len(report.recommendations) == 0

    def test_analyze_without_remediation_plan(self):
        """Test analysis without remediation plan."""
        config = PolicyEngineConfig(include_remediation_plan=False)
        engine = PolicyEngine(config=config)
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]

        report = engine.analyze("scan-123", findings)

        assert report.remediation_plan is None

    def test_quick_analyze(self):
        """Test quick analysis."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
            create_test_finding("f2", AttackCategory.SECRETS_EXPOSURE, Severity.HIGH),
        ]

        result = engine.quick_analyze(findings)

        assert "risk_score" in result
        assert "total_findings" in result
        assert "immediate_actions_needed" in result
        assert "top_recommendations" in result
        assert "compliance_gaps" in result

    def test_quick_analyze_limits_recommendations(self):
        """Test that quick analyze limits recommendations."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL),
        ]

        result = engine.quick_analyze(findings)

        # Should have max 5 top recommendations
        assert len(result["top_recommendations"]) <= 5


class TestPolicyEngineComplianceGaps:
    """Tests for compliance gap identification."""

    def test_identifies_owasp_gaps(self):
        """Test identifying OWASP compliance gaps."""
        engine = PolicyEngine()
        finding = Finding(
            id="f1",
            title="Test",
            description="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            component_type=ComponentType.MODEL,
            component_name="test-model",
            file_path="test.py",
            owasp_ids=["LLM01", "LLM02"],
        )

        report = engine.analyze("scan-123", [finding])

        assert "LLM01" in report.compliance_gaps
        assert "LLM02" in report.compliance_gaps

    def test_identifies_cwe_gaps(self):
        """Test identifying CWE compliance gaps."""
        engine = PolicyEngine()
        finding = Finding(
            id="f1",
            title="Test",
            description="Test",
            category=AttackCategory.SECRETS_EXPOSURE,
            severity=Severity.HIGH,
            component_type=ComponentType.CONFIG,
            component_name="test-config",
            file_path="test.py",
            cwe_ids=["CWE-798", "CWE-200"],
        )

        report = engine.analyze("scan-123", [finding])

        assert "CWE-798" in report.compliance_gaps
        assert "CWE-200" in report.compliance_gaps

    def test_identifies_mitre_gaps(self):
        """Test identifying MITRE ATT&CK gaps."""
        engine = PolicyEngine()
        finding = Finding(
            id="f1",
            title="Test",
            description="Test",
            category=AttackCategory.MODEL_THEFT,
            severity=Severity.HIGH,
            component_type=ComponentType.MODEL,
            component_name="test-model",
            file_path="test.py",
            mitre_ids=["AML.T0003"],
        )

        report = engine.analyze("scan-123", [finding])

        assert "AML.T0003" in report.compliance_gaps


# =============================================================================
# Integration Tests
# =============================================================================

class TestPolicyEngineIntegration:
    """Integration tests for the policy engine."""

    def test_full_analysis_workflow(self):
        """Test complete analysis workflow."""
        # Create realistic findings
        findings = [
            Finding(
                id="f1",
                title="Prompt Injection Vulnerability",
                description="User input passed directly to model",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.CRITICAL,
                component_type=ComponentType.MODEL,
                component_name="inference-api",
                file_path="api/inference.py",
                line_number=45,
                owasp_ids=["LLM01"],
            ),
            Finding(
                id="f2",
                title="Exposed API Key",
                description="API key found in configuration file",
                category=AttackCategory.SECRETS_EXPOSURE,
                severity=Severity.CRITICAL,
                component_type=ComponentType.CONFIG,
                component_name="env-config",
                file_path=".env",
                cwe_ids=["CWE-798"],
            ),
            Finding(
                id="f3",
                title="Missing Rate Limiting",
                description="No rate limiting on inference endpoint",
                category=AttackCategory.DENIAL_OF_SERVICE,
                severity=Severity.HIGH,
                component_type=ComponentType.INFRASTRUCTURE,
                component_name="model-deployment",
                file_path="kubernetes/deployment.yaml",
            ),
        ]

        # Run analysis
        engine = PolicyEngine()
        report = engine.analyze("integration-test-scan", findings)

        # Verify comprehensive output
        assert report.total_findings == 3
        assert report.risk_score > 50  # High risk due to critical findings
        assert len(report.required_guardrails) > 0
        assert len(report.recommendations) > 0
        assert report.remediation_plan is not None
        assert len(report.remediation_plan.actions) > 0
        assert len(report.compliance_gaps) > 0
        assert len(report.markdown_report) > 100

    def test_report_can_be_serialized(self):
        """Test that report can be fully serialized."""
        engine = PolicyEngine()
        findings = [
            create_test_finding("f1", AttackCategory.PROMPT_INJECTION, Severity.HIGH),
        ]

        report = engine.analyze("test-scan", findings)

        # Should be able to convert to dict without errors
        report_dict = report.to_dict()

        # Verify structure
        assert isinstance(report_dict, dict)
        assert "scan_id" in report_dict
        assert "recommendations" in report_dict
        assert isinstance(report_dict["recommendations"], list)
