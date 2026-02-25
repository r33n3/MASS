"""Tests for the LLM verification phase."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from mass.analyzers.code_security.scanner import SecurityCandidate
from mass.analyzers.code_security.patterns import SecurityCategory
from mass.analyzers.code_security.verifier import (
    CodeSecurityVerifier,
    VerificationResult,
    _parse_llm_response,
)
from mass.core.types import Severity


def _make_candidate(
    rule_id: str = "CS-010",
    severity: Severity = Severity.HIGH,
    category: SecurityCategory = SecurityCategory.INJECTION_SQL,
    file_path: str = "app.py",
    line_number: int = 10,
) -> SecurityCandidate:
    """Create a test candidate."""
    return SecurityCandidate(
        rule_id=rule_id,
        pattern_name="test_pattern",
        category=category,
        severity=severity,
        description="Test vulnerability",
        file_path=file_path,
        line_number=line_number,
        matched_line='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        context_before=["import sqlite3", "", "def search(uid):"],
        context_after=["    return cursor.fetchall()", "", ""],
        cwe_ids=["CWE-89"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use parameterized queries.",
    )


class TestParseResponse:
    """Test LLM response parsing."""

    def test_parse_json_array(self):
        """Parse direct JSON array."""
        raw = json.dumps([
            {"candidate_index": 0, "keep_finding": True, "confidence": 0.9}
        ])
        result = _parse_llm_response(raw)
        assert result is not None
        assert len(result) == 1
        assert result[0]["keep_finding"] is True

    def test_parse_json_object(self):
        """Parse single JSON object (wraps in array)."""
        raw = json.dumps(
            {"candidate_index": 0, "keep_finding": False, "confidence": 0.3}
        )
        result = _parse_llm_response(raw)
        assert result is not None
        assert len(result) == 1
        assert result[0]["keep_finding"] is False

    def test_parse_markdown_block(self):
        """Parse JSON from markdown code block."""
        raw = '```json\n[{"candidate_index": 0, "keep_finding": true, "confidence": 0.85}]\n```'
        result = _parse_llm_response(raw)
        assert result is not None
        assert result[0]["confidence"] == 0.85

    def test_parse_with_surrounding_text(self):
        """Parse JSON array embedded in text."""
        raw = 'Here are my findings:\n[{"candidate_index": 0, "keep_finding": true, "confidence": 0.8}]\nEnd.'
        result = _parse_llm_response(raw)
        assert result is not None

    def test_parse_empty(self):
        """Empty input returns None."""
        assert _parse_llm_response("") is None
        assert _parse_llm_response("   ") is None

    def test_parse_garbage(self):
        """Unparseable input returns None."""
        assert _parse_llm_response("This is not JSON at all.") is None


class TestCodeSecurityVerifier:
    """Test the verifier with mocked LLM calls."""

    @pytest.mark.asyncio
    async def test_verify_candidates_success(self):
        """Successful verification with keep_finding=True."""
        verifier = CodeSecurityVerifier(min_confidence=0.7)
        candidate = _make_candidate()

        mock_response = json.dumps([{
            "candidate_index": 0,
            "keep_finding": True,
            "confidence": 0.9,
            "severity": "high",
            "exploit_scenario": "Attacker passes uid=1 OR 1=1",
            "data_flow_trace": "request -> uid -> cursor.execute",
            "remediation": "Use parameterized queries",
        }])

        with patch.object(verifier, "_call_llm", new_callable=AsyncMock, return_value=mock_response):
            results = await verifier.verify_candidates([candidate])

        assert len(results) == 1
        c, v = results[0]
        assert v.keep_finding is True
        assert v.confidence == 0.9
        assert v.severity_adjustment == Severity.HIGH
        assert "1 OR 1=1" in v.exploit_scenario

    @pytest.mark.asyncio
    async def test_verify_candidates_rejected(self):
        """Low confidence candidates are rejected."""
        verifier = CodeSecurityVerifier(min_confidence=0.7)
        candidate = _make_candidate()

        mock_response = json.dumps([{
            "candidate_index": 0,
            "keep_finding": True,
            "confidence": 0.3,
            "severity": "low",
        }])

        with patch.object(verifier, "_call_llm", new_callable=AsyncMock, return_value=mock_response):
            results = await verifier.verify_candidates([candidate])

        assert len(results) == 1
        _, v = results[0]
        assert v.keep_finding is False  # Confidence below threshold

    @pytest.mark.asyncio
    async def test_verify_batch_grouping(self):
        """Multiple candidates are batched correctly."""
        verifier = CodeSecurityVerifier(min_confidence=0.7)
        candidates = [_make_candidate(line_number=i + 1) for i in range(3)]

        mock_response = json.dumps([
            {"candidate_index": 0, "keep_finding": True, "confidence": 0.9},
            {"candidate_index": 1, "keep_finding": False, "confidence": 0.4},
            {"candidate_index": 2, "keep_finding": True, "confidence": 0.8},
        ])

        with patch.object(verifier, "_call_llm", new_callable=AsyncMock, return_value=mock_response):
            results = await verifier.verify_candidates(candidates)

        assert len(results) == 3
        assert results[0][1].keep_finding is True
        assert results[1][1].keep_finding is False
        assert results[2][1].keep_finding is True

    @pytest.mark.asyncio
    async def test_verify_llm_failure_graceful(self):
        """LLM failure should still return candidates with low confidence."""
        verifier = CodeSecurityVerifier(min_confidence=0.7)
        candidate = _make_candidate()

        with patch.object(
            verifier, "_call_llm", new_callable=AsyncMock,
            side_effect=Exception("Connection refused"),
        ):
            results = await verifier.verify_candidates([candidate])

        assert len(results) == 1
        _, v = results[0]
        assert v.keep_finding is True  # Kept but low confidence
        assert v.confidence == 0.4

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        """Progress callback should be called."""
        verifier = CodeSecurityVerifier(min_confidence=0.7)
        candidates = [_make_candidate(line_number=i + 1) for i in range(3)]

        mock_response = json.dumps([
            {"candidate_index": i, "keep_finding": True, "confidence": 0.9}
            for i in range(3)
        ])

        progress_calls = []
        def progress_cb(current, total):
            progress_calls.append((current, total))

        with patch.object(verifier, "_call_llm", new_callable=AsyncMock, return_value=mock_response):
            await verifier.verify_candidates(candidates, progress_cb=progress_cb)

        assert len(progress_calls) > 0
        assert progress_calls[-1][0] == 3

    @pytest.mark.asyncio
    async def test_empty_candidates(self):
        """Empty candidate list should return empty results."""
        verifier = CodeSecurityVerifier()
        results = await verifier.verify_candidates([])
        assert results == []
