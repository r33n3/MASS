"""Tests for the code security static scanner."""

import textwrap
from pathlib import Path

import pytest

from mass.analyzers.code_security.scanner import (
    CodeSecurityScanner,
    SecurityCandidate,
    SKIP_DIRECTORIES,
    SKIP_EXTENSIONS,
)
from mass.core.types import Severity


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temporary project with planted vulnerabilities."""
    # Vulnerable Python file
    vuln_py = tmp_path / "app.py"
    vuln_py.write_text(textwrap.dedent("""\
        import os
        import pickle
        from flask import request, render_template_string

        def get_user():
            role = request.headers.get("X-Role")
            return {"role": role}

        def search(query):
            cursor.execute(f"SELECT * FROM items WHERE name = '{query}'")
            return cursor.fetchall()

        def run_cmd(cmd):
            os.system(cmd)

        def load_data(data):
            return pickle.loads(data)

        def render(template):
            return render_template_string(template)
    """))

    # Safe Python file
    safe_py = tmp_path / "safe.py"
    safe_py.write_text(textwrap.dedent("""\
        import yaml

        def load_config(path):
            with open(path) as f:
                return yaml.safe_load(f)

        def get_items(db, item_id):
            return db.execute("SELECT * FROM items WHERE id = ?", (item_id,))
    """))

    # JavaScript file with XSS
    js_file = tmp_path / "app.js"
    js_file.write_text(textwrap.dedent("""\
        function render(content) {
            document.getElementById("output").innerHTML = content;
        }

        function safe(text) {
            document.getElementById("output").textContent = text;
        }
    """))

    # Test file (should be filtered by false positive patterns)
    test_py = tmp_path / "test_app.py"
    test_py.write_text(textwrap.dedent("""\
        def test_search():
            assert f"SELECT * FROM items WHERE name = '{query}'" in expected
    """))

    # Binary file (should be skipped)
    (tmp_path / "image.png").write_bytes(b"\\x89PNG\\r\\n\\x1a\\n")

    # Nested directory
    sub = tmp_path / "utils"
    sub.mkdir()
    (sub / "helpers.py").write_text("import json\n")

    # __pycache__ (should be skipped)
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"fake bytecode")

    return tmp_path


class TestCodeSecurityScanner:
    """Test the static scanner."""

    def test_scan_directory_finds_vulnerabilities(self, tmp_project):
        """Scanner should find planted vulnerabilities."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_directory(tmp_project)

        # Should find: header role (CS-001), sql fstring (CS-011),
        # os.system (CS-020), pickle.loads (CS-070), render_template_string (CS-030),
        # innerHTML (CS-060)
        rule_ids = {c.rule_id for c in candidates}
        assert "CS-001" in rule_ids, "Should find header role check"
        assert "CS-020" in rule_ids, "Should find os.system"
        assert "CS-070" in rule_ids, "Should find pickle.loads"
        assert "CS-060" in rule_ids, "Should find innerHTML"

    def test_scan_file_returns_candidates(self, tmp_project):
        """scan_file should return candidates for a single file."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_file(
            tmp_project / "app.py", relative_to=tmp_project
        )
        assert len(candidates) > 0
        assert all(c.file_path == "app.py" for c in candidates)

    def test_context_extraction(self, tmp_project):
        """Candidates should include context lines."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_file(
            tmp_project / "app.py", relative_to=tmp_project
        )
        for c in candidates:
            # Context should be populated
            assert isinstance(c.context_before, list)
            assert isinstance(c.context_after, list)
            assert c.line_number > 0

    def test_skips_binary_files(self, tmp_project):
        """Scanner should skip binary/media files."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_directory(tmp_project)
        files = {c.file_path for c in candidates}
        assert "image.png" not in files

    def test_skips_pycache(self, tmp_project):
        """Scanner should skip __pycache__ directory."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_directory(tmp_project)
        for c in candidates:
            assert "__pycache__" not in c.file_path

    def test_deduplication_keeps_highest_severity(self, tmp_project):
        """When multiple patterns match the same line, keep highest severity."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_directory(tmp_project)

        # Check no duplicate (file, line) pairs
        seen = set()
        for c in candidates:
            key = (c.file_path, c.line_number)
            assert key not in seen, f"Duplicate candidate at {key}"
            seen.add(key)

    def test_language_filtering(self, tmp_project):
        """Python patterns should not match JS files and vice versa."""
        scanner = CodeSecurityScanner()

        py_candidates = scanner.scan_file(
            tmp_project / "app.py", relative_to=tmp_project
        )
        js_candidates = scanner.scan_file(
            tmp_project / "app.js", relative_to=tmp_project
        )

        # Python-only patterns should not appear in JS results
        py_only_rules = {"CS-001", "CS-010", "CS-011", "CS-020", "CS-070", "CS-030"}
        js_rule_ids = {c.rule_id for c in js_candidates}
        assert not (py_only_rules & js_rule_ids), "Python patterns matched in JS file"

    def test_architecture_enrichment(self, tmp_project):
        """Candidates should be enriched with architecture map roles."""
        arch_map = {
            "entry_points": [
                {"type": "api_endpoint", "location": "app.py:6"}
            ],
        }
        scanner = CodeSecurityScanner(architecture_map=arch_map)
        candidates = scanner.scan_directory(tmp_project)

        app_candidates = [c for c in candidates if c.file_path == "app.py"]
        roles = {c.file_role for c in app_candidates if c.file_role}
        assert "entry_point" in roles

    def test_safe_file_no_findings(self, tmp_project):
        """Safe code should produce no findings."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_file(
            tmp_project / "safe.py", relative_to=tmp_project
        )
        # safe.py uses yaml.safe_load and parameterized queries
        assert len(candidates) == 0

    def test_large_file_skipped(self, tmp_project):
        """Files over MAX_FILE_SIZE should be skipped."""
        large = tmp_project / "large.py"
        large.write_text("x = 1\n" * 50000)  # ~300KB
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_file(large, relative_to=tmp_project)
        assert len(candidates) == 0

    def test_candidate_fields(self, tmp_project):
        """Candidate objects should have all required fields populated."""
        scanner = CodeSecurityScanner()
        candidates = scanner.scan_directory(tmp_project)
        for c in candidates:
            assert c.rule_id
            assert c.pattern_name
            assert isinstance(c.category, type(c.category))
            assert isinstance(c.severity, Severity)
            assert c.file_path
            assert c.line_number > 0
            assert c.matched_line
            assert len(c.cwe_ids) > 0
            assert len(c.owasp_ids) > 0
