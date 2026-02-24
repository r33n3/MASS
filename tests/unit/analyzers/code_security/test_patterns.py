"""Tests for code security pattern definitions."""

import re

import pytest

from mass.analyzers.code_security.patterns import (
    CATEGORY_MAPPING,
    LANGUAGE_EXTENSIONS,
    SECURITY_PATTERNS,
    SecurityCategory,
    SecurityPattern,
)
from mass.core.types import AttackCategory, Severity


class TestPatternDefinitions:
    """Test that all patterns are well-formed."""

    def test_all_patterns_compile(self):
        """Every pattern's regex should be pre-compiled."""
        for p in SECURITY_PATTERNS:
            assert isinstance(p.pattern, re.Pattern), f"{p.rule_id} pattern not compiled"

    def test_all_patterns_have_rule_ids(self):
        """Every pattern must have a unique rule_id starting with CS-."""
        ids = set()
        for p in SECURITY_PATTERNS:
            assert p.rule_id.startswith("CS-"), f"{p.rule_id} doesn't start with CS-"
            assert p.rule_id not in ids, f"Duplicate rule_id: {p.rule_id}"
            ids.add(p.rule_id)

    def test_all_patterns_have_cwe_ids(self):
        """Every pattern must have at least one CWE ID."""
        for p in SECURITY_PATTERNS:
            assert len(p.cwe_ids) > 0, f"{p.rule_id} missing CWE IDs"
            for cwe in p.cwe_ids:
                assert cwe.startswith("CWE-"), f"{p.rule_id} invalid CWE: {cwe}"

    def test_all_patterns_have_owasp_ids(self):
        """Every pattern must have at least one OWASP ID."""
        for p in SECURITY_PATTERNS:
            assert len(p.owasp_ids) > 0, f"{p.rule_id} missing OWASP IDs"

    def test_all_patterns_have_languages(self):
        """Every pattern must specify at least one language."""
        for p in SECURITY_PATTERNS:
            assert len(p.languages) > 0, f"{p.rule_id} missing languages"
            for lang in p.languages:
                assert lang in LANGUAGE_EXTENSIONS, f"{p.rule_id} unknown language: {lang}"

    def test_all_categories_mapped(self):
        """Every SecurityCategory must map to an AttackCategory."""
        for cat in SecurityCategory:
            assert cat in CATEGORY_MAPPING, f"{cat} not in CATEGORY_MAPPING"
            assert isinstance(CATEGORY_MAPPING[cat], AttackCategory)

    def test_false_positive_patterns_compile(self):
        """All false positive patterns should be compiled."""
        for p in SECURITY_PATTERNS:
            for fp in p.false_positive_patterns:
                assert isinstance(fp, re.Pattern), (
                    f"{p.rule_id} false positive pattern not compiled"
                )

    def test_pattern_count(self):
        """Should have approximately 35 patterns."""
        assert len(SECURITY_PATTERNS) >= 30, f"Only {len(SECURITY_PATTERNS)} patterns"


class TestPatternMatching:
    """Test patterns against known vulnerable code snippets."""

    def test_cs001_header_role(self):
        """CS-001: Header-based role without verification."""
        p = _get_pattern("CS-001")
        assert p.pattern.search('role = request.headers.get("X-Role")')
        assert p.pattern.search("request.headers.get('x-is-admin')")
        assert not p.pattern.search('request.headers.get("content-type")')

    def test_cs003_jwt_no_verify(self):
        """CS-003: JWT decode without verification."""
        p = _get_pattern("CS-003")
        assert p.pattern.search("jwt.decode(token, verify=False)")
        assert not p.pattern.search('jwt.decode(token, key, algorithms=["HS256"])')

    def test_cs010_sql_fstring(self):
        """CS-010: SQL injection via f-string."""
        p = _get_pattern("CS-010")
        assert p.pattern.search('f"SELECT * FROM users WHERE id = {user_id}"')
        assert p.pattern.search("f'DELETE FROM logs WHERE date < {cutoff}'")
        assert not p.pattern.search('"SELECT * FROM users WHERE id = ?"')

    def test_cs011_cursor_fstring(self):
        """CS-011: cursor.execute() with f-string."""
        p = _get_pattern("CS-011")
        assert p.pattern.search('cursor.execute(f"SELECT * FROM {table}")')
        assert not p.pattern.search('cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))')

    def test_cs020_os_system(self):
        """CS-020: os.system() call."""
        p = _get_pattern("CS-020")
        assert p.pattern.search("os.system(cmd)")
        assert p.pattern.search('os.system("ls")')

    def test_cs022_eval(self):
        """CS-022: eval() call."""
        p = _get_pattern("CS-022")
        assert p.pattern.search("eval(user_input)")
        assert not p.pattern.search("ast.literal_eval(data)")

    def test_cs040_llm_fstring(self):
        """CS-040: User input in LLM prompt f-string."""
        p = _get_pattern("CS-040")
        assert p.pattern.search('f"System prompt: {user_input}"')
        assert p.pattern.search('f"Instruction: analyze this {query}"')

    def test_cs050_raw_request_json(self):
        """CS-050: Raw request.json() without validation."""
        p = _get_pattern("CS-050")
        assert p.pattern.search("body = await request.json()")
        assert p.pattern.search("data = request.json()")

    def test_cs060_innerhtml(self):
        """CS-060: innerHTML assignment."""
        p = _get_pattern("CS-060")
        assert p.pattern.search('element.innerHTML = userContent')

    def test_cs070_pickle(self):
        """CS-070: pickle.loads() call."""
        p = _get_pattern("CS-070")
        assert p.pattern.search("pickle.loads(data)")
        assert p.pattern.search("pickle.load(file)")

    def test_cs071_yaml_unsafe(self):
        """CS-071: yaml.load() without SafeLoader."""
        p = _get_pattern("CS-071")
        assert p.pattern.search("yaml.load(data)")
        # SafeLoader in false positive patterns
        fp_match = any(fp.search("yaml.load(data, Loader=yaml.SafeLoader)") for fp in p.false_positive_patterns)
        assert fp_match

    def test_cs080_cors_wildcard(self):
        """CS-080: CORS wildcard origin."""
        p = _get_pattern("CS-080")
        assert p.pattern.search('allow_origins=["*"]')
        assert p.pattern.search("origins=['*']")

    def test_cs090_log_password(self):
        """CS-090: Logging sensitive data."""
        p = _get_pattern("CS-090")
        assert p.pattern.search('logger.info("Auth: password=%s", password)')
        assert p.pattern.search("print(api_key)")


class TestFalsePositivePatterns:
    """Test that false positive patterns correctly reject safe code."""

    def test_cs010_test_file_excluded(self):
        """CS-010: Test assertions should be excluded."""
        p = _get_pattern("CS-010")
        line = 'assert f"SELECT * FROM users WHERE id = {uid}" in queries'
        is_fp = any(fp.search(line) for fp in p.false_positive_patterns)
        assert is_fp

    def test_cs022_literal_eval_excluded(self):
        """CS-022: ast.literal_eval should be excluded."""
        p = _get_pattern("CS-022")
        line = "result = ast.literal_eval(data)"
        is_fp = any(fp.search(line) for fp in p.false_positive_patterns)
        assert is_fp

    def test_cs090_masked_excluded(self):
        """CS-090: Masked/redacted data should be excluded."""
        p = _get_pattern("CS-090")
        line = 'logger.info("password: %s", mask(password))'
        is_fp = any(fp.search(line) for fp in p.false_positive_patterns)
        assert is_fp


def _get_pattern(rule_id: str) -> SecurityPattern:
    """Helper to get a pattern by rule_id."""
    for p in SECURITY_PATTERNS:
        if p.rule_id == rule_id:
            return p
    raise ValueError(f"Pattern {rule_id} not found")
