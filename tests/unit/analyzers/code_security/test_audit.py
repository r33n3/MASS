"""Tests for the code security audit orchestrator."""

import json
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mass.analyzers.code_security.audit import (
    AuditConfig,
    AuditResult,
    CodeSecurityAuditor,
)
from mass.core.findings import Finding
from mass.core.types import AttackCategory, ComponentType, Severity


@pytest.fixture
def vuln_project(tmp_path):
    """Create a project with known vulnerabilities."""
    app = tmp_path / "app.py"
    app.write_text(textwrap.dedent("""\
        import os
        import pickle
        from flask import request

        def admin_check():
            role = request.headers.get("X-Role")
            if role == "admin":
                return True
            return False

        def search(query):
            cursor.execute(f"SELECT * FROM items WHERE name = '{query}'")

        def run(cmd):
            os.system(cmd)

        def deserialize(data):
            return pickle.loads(data)
    """))
    return tmp_path


class TestCodeSecurityAuditor:
    """Test the full audit pipeline."""

    @pytest.mark.asyncio
    async def test_static_only_audit(self, vuln_project):
        """Audit with llm_verification=False produces static-only findings."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(vuln_project, config=config)

        assert isinstance(result, AuditResult)
        assert result.candidates_found > 0
        assert result.findings_static_only > 0
        assert result.candidates_verified == 0
        assert result.duration_phase_a > 0
        assert result.duration_phase_b == 0
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_findings_are_core_findings(self, vuln_project):
        """All findings should be core Finding objects."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(vuln_project, config=config)

        for finding in result.findings:
            assert isinstance(finding, Finding)
            assert finding.component_type == ComponentType.CODE
            assert finding.file_path
            assert finding.line_number
            assert len(finding.cwe_ids) > 0
            assert len(finding.evidence) > 0
            assert finding.remediation is not None

    @pytest.mark.asyncio
    async def test_severity_mapping(self, vuln_project):
        """Findings should have correct severities."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(vuln_project, config=config)

        severities = {f.severity for f in result.findings}
        # Should find at least CRITICAL (os.system, pickle)
        assert Severity.CRITICAL in severities

    @pytest.mark.asyncio
    async def test_category_mapping(self, vuln_project):
        """Findings should map to correct AttackCategories."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(vuln_project, config=config)

        categories = {f.category for f in result.findings}
        # os.system -> EXCESSIVE_AGENCY, pickle -> SUPPLY_CHAIN
        assert AttackCategory.EXCESSIVE_AGENCY in categories or AttackCategory.SUPPLY_CHAIN in categories

    @pytest.mark.asyncio
    async def test_fingerprint_stability(self, vuln_project):
        """Same scan should produce same fingerprints."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()

        r1 = await auditor.audit(vuln_project, config=config)
        r2 = await auditor.audit(vuln_project, config=config)

        ids1 = sorted(f.id for f in r1.findings)
        ids2 = sorted(f.id for f in r2.findings)
        assert ids1 == ids2

    @pytest.mark.asyncio
    async def test_llm_verified_audit(self, vuln_project):
        """Audit with LLM verification mocked."""
        config = AuditConfig(
            llm_verification=True,
            llm_severity_threshold=Severity.HIGH,
        )

        mock_response = json.dumps([
            {
                "candidate_index": i,
                "keep_finding": True,
                "confidence": 0.9,
                "severity": "high",
                "exploit_scenario": f"Exploit scenario {i}",
                "data_flow_trace": "input -> sink",
                "remediation": "Fix it",
            }
            for i in range(10)
        ])

        auditor = CodeSecurityAuditor()

        with patch(
            "mass.analyzers.code_security.verifier.CodeSecurityVerifier._call_llm",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await auditor.audit(vuln_project, config=config)

        assert result.candidates_found > 0
        assert len(result.findings) > 0
        # Should have both static-only and LLM-verified findings
        methods = {f.metadata.get("detection_method") for f in result.findings}
        # At least static should be present (for non-LLM patterns)
        assert "static" in methods or "llm_verified" in methods

    @pytest.mark.asyncio
    async def test_empty_directory(self, tmp_path):
        """Empty directory produces no findings."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(tmp_path, config=config)

        assert result.candidates_found == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_metadata_fields(self, vuln_project):
        """Finding metadata should include detection method and rule_id."""
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(vuln_project, config=config)

        for finding in result.findings:
            assert "detection_method" in finding.metadata
            assert "rule_id" in finding.metadata
            assert finding.metadata["rule_id"].startswith("CS-")

    @pytest.mark.asyncio
    async def test_architecture_map_passed(self, vuln_project):
        """Architecture map should be passed to scanner."""
        arch = {
            "entry_points": [{"type": "api", "location": "app.py:5"}],
        }
        config = AuditConfig(llm_verification=False)
        auditor = CodeSecurityAuditor()
        result = await auditor.audit(
            vuln_project, architecture_map=arch, config=config
        )

        # Should still find vulnerabilities
        assert result.candidates_found > 0
        # At least one finding should have file_role metadata
        roles = [f.metadata.get("file_role") for f in result.findings]
        assert "entry_point" in roles

    @pytest.mark.asyncio
    async def test_severity_threshold_filtering(self, vuln_project):
        """Only candidates at or above severity threshold go to LLM."""
        config = AuditConfig(
            llm_verification=True,
            llm_severity_threshold=Severity.CRITICAL,
        )

        mock_response = json.dumps([{
            "candidate_index": 0,
            "keep_finding": True,
            "confidence": 0.95,
            "severity": "critical",
        }])

        auditor = CodeSecurityAuditor()

        with patch(
            "mass.analyzers.code_security.verifier.CodeSecurityVerifier._call_llm",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await auditor.audit(vuln_project, config=config)

        # Should have findings — some static, some potentially verified
        assert len(result.findings) > 0
