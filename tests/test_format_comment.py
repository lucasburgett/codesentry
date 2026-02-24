"""Tests for _format_comment output formatting."""

from app.main import _format_comment


class TestFormatComment:
    def test_no_findings_no_llm(self):
        result = _format_comment([("app.py", 0.9)], [], head_sha="abc1234def")
        assert "CodeSentry Analysis" in result
        assert "No issues found" in result
        assert "Behavioral summary unavailable" in result
        assert "abc1234" in result

    def test_single_error_finding(self):
        findings = [{
            "rule_id": "hardcoded-secret-string",
            "category": "security",
            "severity": "error",
            "file_path": "app.py",
            "line_start": 3,
            "message": "Hardcoded secret.",
        }]
        result = _format_comment([("app.py", 0.9)], findings, head_sha="abc1234")
        assert "High" in result
        assert "hardcoded-secret-string" in result
        assert "**L3**" in result
        assert "**Issues:** 1" in result
        assert "1 finding" in result

    def test_mixed_severities(self):
        findings = [
            {"rule_id": "r1", "category": "security", "severity": "error",
             "file_path": "a.py", "line_start": 1, "message": "err"},
            {"rule_id": "r2", "category": "correctness", "severity": "warning",
             "file_path": "a.py", "line_start": 5, "message": "warn"},
            {"rule_id": "r3", "category": "quality", "severity": "info",
             "file_path": "b.py", "line_start": 10, "message": "info"},
        ]
        result = _format_comment(
            [("a.py", 0.9), ("b.py", 0.6)], findings, head_sha="abc",
        )
        assert "High" in result
        assert "**Issues:** 3" in result
        assert "3 findings" in result

    def test_multiple_files_sorted(self):
        result = _format_comment(
            [("z.py", 0.5), ("a.py", 0.9)], [],
            head_sha="abc",
        )
        assert result.index("a.py") < result.index("z.py")

    def test_semgrep_error_message(self):
        result = _format_comment(
            [("app.py", 0.9)], [],
            head_sha="abc",
            semgrep_error="Semgrep timed out after 120s",
        )
        assert "Static analysis error" in result
        assert "timed out" in result

    def test_with_llm_summary(self):
        result = _format_comment(
            [("app.py", 0.9)], [],
            head_sha="abc1234",
            llm_summary="This code adds a new authentication endpoint.",
        )
        assert "What this code does" in result
        assert "authentication endpoint" in result
        assert "Behavioral summary unavailable" not in result

    def test_with_behavioral_flags(self):
        flags = [
            {"flag": "No rate limiting", "severity": "high", "location": "api.py:42"},
            {"flag": "Missing validation", "severity": "medium", "location": ""},
        ]
        result = _format_comment(
            [("api.py", 0.9)], [],
            head_sha="abc",
            llm_summary="Adds an API.",
            behavioral_flags=flags,
        )
        assert "Behavioral Analysis" in result
        assert "No rate limiting" in result
        assert "Missing validation" in result
        assert "**Issues:** 2" in result
        assert "No static analysis issues" in result
        assert "No issues found." not in result
        assert "**L42**" in result
        assert result.index("No static analysis issues") < result.index("Behavioral Analysis")

    def test_risk_medium_from_warnings(self):
        findings = [
            {"rule_id": "r1", "category": "correctness", "severity": "warning",
             "file_path": "a.py", "line_start": 1, "message": "warn"},
        ]
        result = _format_comment([("a.py", 0.9)], findings, head_sha="abc")
        assert "Medium" in result
        assert "🟡" in result

    def test_risk_low_when_clean(self):
        result = _format_comment([("a.py", 0.9)], [], head_sha="abc")
        assert "Low" in result
        assert "🟢" in result

    def test_risk_low_from_behavioral_flag_alone(self):
        flags = [{"flag": "Critical", "severity": "high", "location": "x.py:1"}]
        result = _format_comment(
            [("x.py", 0.9)], [], head_sha="abc",
            llm_summary="test", behavioral_flags=flags,
        )
        assert "Low" in result
        assert "🟢" in result

    def test_risk_high_requires_semgrep_error(self):
        flags = [{"flag": "Critical", "severity": "high", "location": "x.py:1"}]
        findings = [{
            "rule_id": "hardcoded-secret", "category": "security",
            "severity": "error", "file_path": "x.py",
            "line_start": 1, "message": "secret",
        }]
        result = _format_comment(
            [("x.py", 0.9)], findings, head_sha="abc",
            llm_summary="test", behavioral_flags=flags,
        )
        assert "High" in result
        assert "🔴" in result

    def test_commit_sha_footer(self):
        result = _format_comment(
            [("app.py", 0.9)], [],
            head_sha="abc1234567890",
        )
        assert "_Analyzed commit `abc1234`_" in result
