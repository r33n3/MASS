"""Tests for compliance assessment module."""

import pytest

from mass.core.findings import Finding
from mass.core.types import (
    AttackCategory,
    ComponentType,
    FrameworkType,
    Severity,
)
from mass.compliance.mappings import (
    ComplianceMapping,
    FrameworkRequirement,
    RequirementStatus,
    get_framework_requirements,
    get_mapping_for_category,
    OWASP_LLM_REQUIREMENTS,
    MITRE_ATLAS_REQUIREMENTS,
    CATEGORY_MAPPINGS,
)
from mass.compliance.assessor import (
    ComplianceAssessor,
    AssessmentResult,
    FrameworkAssessment,
    RequirementAssessment,
)


class TestFrameworkRequirement:
    """Tests for FrameworkRequirement."""

    def test_requirement_creation(self):
        """Test creating a framework requirement."""
        req = FrameworkRequirement(
            id="TEST-01",
            name="Test Requirement",
            description="A test requirement",
            framework=FrameworkType.OWASP_LLM,
        )
        assert req.id == "TEST-01"
        assert req.framework == FrameworkType.OWASP_LLM
        assert req.status == RequirementStatus.NOT_ASSESSED

    def test_requirement_to_dict(self):
        """Test requirement serialization."""
        req = FrameworkRequirement(
            id="TEST-01",
            name="Test Requirement",
            description="A test",
            framework=FrameworkType.OWASP_LLM,
        )
        data = req.to_dict()
        assert data["id"] == "TEST-01"
        assert data["framework"] == "owasp_llm"


class TestComplianceMapping:
    """Tests for ComplianceMapping."""

    def test_mapping_creation(self):
        """Test creating a compliance mapping."""
        mapping = ComplianceMapping(
            category=AttackCategory.PROMPT_INJECTION,
            owasp_llm=["LLM01"],
            mitre_atlas=["AML.T0015"],
        )
        assert mapping.category == AttackCategory.PROMPT_INJECTION
        assert "LLM01" in mapping.owasp_llm


class TestGetFrameworkRequirements:
    """Tests for get_framework_requirements function."""

    def test_get_owasp_llm_requirements(self):
        """Test getting OWASP LLM requirements."""
        reqs = get_framework_requirements(FrameworkType.OWASP_LLM)
        assert len(reqs) == 10
        assert "LLM01" in reqs
        assert "LLM10" in reqs

    def test_get_mitre_atlas_requirements(self):
        """Test getting MITRE ATLAS requirements."""
        reqs = get_framework_requirements(FrameworkType.MITRE_ATLAS)
        assert len(reqs) > 0
        assert "AML.T0015" in reqs

    def test_get_nist_requirements(self):
        """Test getting NIST AI RMF requirements."""
        reqs = get_framework_requirements(FrameworkType.NIST_AI_RMF)
        assert len(reqs) > 0
        assert "GOVERN-1" in reqs

    def test_get_eu_ai_act_requirements(self):
        """Test getting EU AI Act requirements."""
        reqs = get_framework_requirements(FrameworkType.EU_AI_ACT)
        assert len(reqs) > 0
        assert "AIA-9" in reqs

    def test_get_unknown_framework(self):
        """Test getting requirements for unknown framework."""
        reqs = get_framework_requirements(FrameworkType.SOC2)
        assert len(reqs) == 0


class TestGetMappingForCategory:
    """Tests for get_mapping_for_category function."""

    def test_get_prompt_injection_mapping(self):
        """Test getting mapping for prompt injection."""
        mapping = get_mapping_for_category(AttackCategory.PROMPT_INJECTION)
        assert mapping is not None
        assert "LLM01" in mapping.owasp_llm
        assert "AML.T0015" in mapping.mitre_atlas

    def test_get_sensitive_info_mapping(self):
        """Test getting mapping for sensitive info."""
        mapping = get_mapping_for_category(AttackCategory.SENSITIVE_INFO)
        assert mapping is not None
        assert "LLM02" in mapping.owasp_llm

    def test_all_categories_have_mappings(self):
        """Test that major categories have mappings."""
        categories_to_check = [
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.SUPPLY_CHAIN,
            AttackCategory.EXCESSIVE_AGENCY,
            AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        ]
        for category in categories_to_check:
            mapping = get_mapping_for_category(category)
            assert mapping is not None, f"Missing mapping for {category}"


class TestOWASPLLMRequirements:
    """Tests for OWASP LLM requirements."""

    def test_llm01_prompt_injection(self):
        """Test LLM01 requirement."""
        req = OWASP_LLM_REQUIREMENTS["LLM01"]
        assert req.name == "Prompt Injection"
        assert req.severity_weight == 1.0

    def test_llm06_excessive_agency(self):
        """Test LLM06 requirement."""
        req = OWASP_LLM_REQUIREMENTS["LLM06"]
        assert req.name == "Excessive Agency"
        assert req.severity_weight == 0.95

    def test_all_owasp_requirements_exist(self):
        """Test all 10 OWASP requirements exist."""
        for i in range(1, 11):
            req_id = f"LLM{i:02d}"
            assert req_id in OWASP_LLM_REQUIREMENTS


class TestRequirementAssessment:
    """Tests for RequirementAssessment."""

    def test_assessment_creation(self):
        """Test creating a requirement assessment."""
        req = OWASP_LLM_REQUIREMENTS["LLM01"]
        assessment = RequirementAssessment(requirement=req)
        assert assessment.status == RequirementStatus.NOT_ASSESSED
        assert len(assessment.findings) == 0

    def test_assessment_to_dict(self):
        """Test assessment serialization."""
        req = OWASP_LLM_REQUIREMENTS["LLM01"]
        assessment = RequirementAssessment(
            requirement=req,
            status=RequirementStatus.COMPLIANT,
        )
        data = assessment.to_dict()
        assert data["requirement_id"] == "LLM01"
        assert data["status"] == "compliant"


class TestFrameworkAssessment:
    """Tests for FrameworkAssessment."""

    def test_assessment_creation(self):
        """Test creating a framework assessment."""
        assessment = FrameworkAssessment(framework=FrameworkType.OWASP_LLM)
        assert assessment.framework == FrameworkType.OWASP_LLM
        assert assessment.compliance_score == 0.0

    def test_calculate_scores_empty(self):
        """Test calculating scores with no requirements."""
        assessment = FrameworkAssessment(framework=FrameworkType.OWASP_LLM)
        assessment.calculate_scores()
        assert assessment.total_requirements == 0

    def test_calculate_scores_all_compliant(self):
        """Test calculating scores when all compliant."""
        assessment = FrameworkAssessment(framework=FrameworkType.OWASP_LLM)
        for req_id, req in OWASP_LLM_REQUIREMENTS.items():
            assessment.requirements[req_id] = RequirementAssessment(
                requirement=req,
                status=RequirementStatus.COMPLIANT,
            )
        assessment.calculate_scores()
        assert assessment.compliance_score == 100.0
        assert assessment.compliant_count == 10

    def test_calculate_scores_mixed(self):
        """Test calculating scores with mixed compliance."""
        assessment = FrameworkAssessment(framework=FrameworkType.OWASP_LLM)

        # Add some compliant and non-compliant
        for i, (req_id, req) in enumerate(OWASP_LLM_REQUIREMENTS.items()):
            status = RequirementStatus.COMPLIANT if i % 2 == 0 else RequirementStatus.NON_COMPLIANT
            assessment.requirements[req_id] = RequirementAssessment(
                requirement=req,
                status=status,
            )

        assessment.calculate_scores()
        assert 0 < assessment.compliance_score < 100
        assert assessment.compliant_count == 5
        assert assessment.non_compliant_count == 5


class TestAssessmentResult:
    """Tests for AssessmentResult."""

    def test_result_creation(self):
        """Test creating an assessment result."""
        result = AssessmentResult(scan_id="scan-123")
        assert result.scan_id == "scan-123"
        assert len(result.frameworks) == 0

    def test_result_to_dict(self):
        """Test result serialization."""
        result = AssessmentResult(scan_id="scan-123")
        data = result.to_dict()
        assert data["scan_id"] == "scan-123"
        assert "overall_compliance_score" in data


class TestComplianceAssessor:
    """Tests for ComplianceAssessor."""

    def test_assessor_creation(self):
        """Test creating an assessor."""
        assessor = ComplianceAssessor()
        assert FrameworkType.OWASP_LLM in assessor.frameworks
        assert FrameworkType.MITRE_ATLAS in assessor.frameworks

    def test_assessor_custom_frameworks(self):
        """Test creating assessor with custom frameworks."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])
        assert len(assessor.frameworks) == 1
        assert FrameworkType.OWASP_LLM in assessor.frameworks

    def test_assess_empty_findings(self):
        """Test assessing empty findings list."""
        assessor = ComplianceAssessor()
        result = assessor.assess([], scan_id="scan-123")

        assert result.scan_id == "scan-123"
        assert result.total_findings == 0
        assert result.overall_compliance_score == 100.0

    def test_assess_with_findings(self):
        """Test assessing findings."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Prompt Injection Detected",
                description="Test finding",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        result = assessor.assess(findings, scan_id="scan-123")

        assert result.total_findings == 1
        assert result.mapped_findings == 1
        # LLM01 should be non-compliant
        owasp = result.frameworks[FrameworkType.OWASP_LLM]
        assert owasp.requirements["LLM01"].status == RequirementStatus.NON_COMPLIANT

    def test_assess_critical_finding(self):
        """Test assessing critical finding."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Critical Issue",
                description="Test",
                severity=Severity.CRITICAL,
                category=AttackCategory.EXCESSIVE_AGENCY,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        result = assessor.assess(findings)
        owasp = result.frameworks[FrameworkType.OWASP_LLM]
        assert owasp.requirements["LLM06"].status == RequirementStatus.NON_COMPLIANT

    def test_assess_medium_finding(self):
        """Test assessing medium finding (partial compliance)."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Medium Issue",
                description="Test",
                severity=Severity.MEDIUM,
                category=AttackCategory.SYSTEM_PROMPT_LEAKAGE,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        result = assessor.assess(findings)
        owasp = result.frameworks[FrameworkType.OWASP_LLM]
        assert owasp.requirements["LLM07"].status == RequirementStatus.PARTIAL

    def test_assess_single_framework(self):
        """Test assessing against single framework."""
        assessor = ComplianceAssessor()
        findings = [
            Finding(
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        assessment = assessor.assess_single_framework(
            findings,
            FrameworkType.OWASP_LLM,
        )
        assert assessment.framework == FrameworkType.OWASP_LLM

    def test_get_non_compliant_requirements(self):
        """Test getting non-compliant requirements."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        result = assessor.assess(findings)
        non_compliant = assessor.get_non_compliant_requirements(result)

        assert len(non_compliant) > 0
        assert any(r.requirement.id == "LLM01" for r in non_compliant)

    def test_generate_compliance_summary(self):
        """Test generating compliance summary."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="test-model",
            ),
        ]

        result = assessor.assess(findings)
        summary = assessor.generate_compliance_summary(result)

        assert "overall" in summary
        assert "frameworks" in summary
        assert "top_issues" in summary
        assert "owasp_llm" in summary["frameworks"]


class TestIntegration:
    """Integration tests for compliance module."""

    def test_full_assessment_workflow(self):
        """Test complete assessment workflow."""
        assessor = ComplianceAssessor(
            frameworks=[
                FrameworkType.OWASP_LLM,
                FrameworkType.MITRE_ATLAS,
            ]
        )

        # Create diverse findings
        findings = [
            Finding(
                title="Prompt Injection",
                description="Direct injection attack",
                severity=Severity.CRITICAL,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="gpt-4",
            ),
            Finding(
                title="System Prompt Leak",
                description="System prompt exposed",
                severity=Severity.HIGH,
                category=AttackCategory.SYSTEM_PROMPT_LEAKAGE,
                component_type=ComponentType.CONTEXT,
                component_name="main-prompt",
            ),
            Finding(
                title="Excessive Tool Access",
                description="Agent has too many permissions",
                severity=Severity.MEDIUM,
                category=AttackCategory.EXCESSIVE_AGENCY,
                component_type=ComponentType.MCP_SERVER,
                component_name="file-access",
            ),
        ]

        result = assessor.assess(findings, scan_id="test-scan")

        # Verify overall assessment
        assert result.total_findings == 3
        assert result.mapped_findings == 3
        assert result.overall_compliance_score < 100

        # Verify framework assessments
        assert FrameworkType.OWASP_LLM in result.frameworks
        assert FrameworkType.MITRE_ATLAS in result.frameworks

        owasp = result.frameworks[FrameworkType.OWASP_LLM]
        assert owasp.non_compliant_count > 0

        # Verify summary generation
        summary = assessor.generate_compliance_summary(result)
        assert float(summary["overall"]["compliance_score"].rstrip("%")) < 100

    def test_multiple_findings_same_category(self):
        """Test multiple findings affecting same requirement."""
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])

        findings = [
            Finding(
                title="Injection 1",
                description="First injection",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="model-1",
            ),
            Finding(
                title="Injection 2",
                description="Second injection",
                severity=Severity.CRITICAL,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="model-2",
            ),
        ]

        result = assessor.assess(findings)
        owasp = result.frameworks[FrameworkType.OWASP_LLM]

        # LLM01 should have both findings
        assert len(owasp.requirements["LLM01"].findings) == 2
        # Should remain non-compliant
        assert owasp.requirements["LLM01"].status == RequirementStatus.NON_COMPLIANT
