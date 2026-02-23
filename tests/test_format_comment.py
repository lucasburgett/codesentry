"""Tests for _format_comment output formatting."""

from app.main import _format_comment


class TestFormatComment:
    def test_no_findings(self):
        result = _format_comment([("app.py", 0.9)], [])
        assert "No issues found" in result
        assert "app.py" in result

    def test_single_error(self):
        findings = [{
            "rule_id": "hardcoded-secret-string",
            "category": "security",
            "severity": "error",
            "file_path": "app.py",
            "line_start": 3,
            "message": "Hardcoded secret.",
        }]
        result = _format_comment([("app.py", 0.9)], findings)
        assert "1 issue" in result
        assert "1 error" in result
        assert "hardcoded-secret-string" in result
        assert "app.py:3" in result

    def test_mixed_severities(self):
        findings = [
            {"rule_id": "r1", "category": "security", "severity": "error",
             "file_path": "a.py", "line_start": 1, "message": "err"},
            {"rule_id": "r2", "category": "correctness", "severity": "warning",
             "file_path": "a.py", "line_start": 5, "message": "warn"},
            {"rule_id": "r3", "category": "quality", "severity": "info",
             "file_path": "b.py", "line_start": 10, "message": "info"},
        ]
        result = _format_comment([("a.py", 0.9), ("b.py", 0.6)], findings)
        assert "3 issues" in result
        assert "1 error" in result
        assert "1 warning" in result
        assert "1 info" in result

    def test_multiple_files_sorted(self):
        result = _format_comment([("z.py", 0.5), ("a.py", 0.9)], [])
        assert result.index("a.py") < result.index("z.py")

    def test_semgrep_error_message(self):
        result = _format_comment(
            [("app.py", 0.9)], [],
            semgrep_error="Semgrep timed out after 120s",
        )
        assert "Static analysis error" in result
        assert "timed out" in result
        assert "No issues" not in result

    def test_plural_errors(self):
        findings = [
            {"rule_id": f"r{i}", "category": "security", "severity": "error",
             "file_path": "x.py", "line_start": i, "message": "msg"}
            for i in range(3)
        ]
        result = _format_comment([("x.py", 0.9)], findings)
        assert "3 errors" in result
