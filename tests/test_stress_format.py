"""Stress tests: comment formatting with extreme and realistic inputs."""

from app.main import _format_comment


def _make_finding(rule_id: str, severity: str = "warning", file_path: str = "a.py",
                  line: int = 1, message: str = "Issue found.") -> dict:
    return {
        "rule_id": rule_id,
        "category": "security" if severity == "error" else "correctness",
        "severity": severity,
        "file_path": file_path,
        "line_start": line,
        "message": message,
    }


class TestManyFindings:
    def test_20_findings_all_listed(self):
        findings = [
            _make_finding(f"rule-{i}", "error" if i % 3 == 0 else "warning", f"file_{i}.py", i + 1)
            for i in range(20)
        ]
        ai_files = [(f"file_{i}.py", 0.9) for i in range(20)]
        result = _format_comment(ai_files, findings, head_sha="abc123")

        assert "CodeSentry Analysis" in result
        assert "**Issues:** 20" in result
        assert "20 findings" in result
        for i in range(20):
            assert f"rule-{i}" in result

    def test_severity_counts_correct(self):
        findings = [
            _make_finding("err-1", "error"),
            _make_finding("err-2", "error"),
            _make_finding("warn-1", "warning"),
            _make_finding("warn-2", "warning"),
            _make_finding("warn-3", "warning"),
            _make_finding("info-1", "info"),
        ]
        result = _format_comment([("a.py", 0.9)], findings, head_sha="abc")
        assert "**Issues:** 6" in result
        assert "High" in result


class TestManyBehavioralFlags:
    def test_10_flags_all_rendered(self):
        flags = [
            {"flag": f"Behavioral issue #{i}", "severity": "medium", "location": f"mod_{i}.py:{i * 10}"}
            for i in range(10)
        ]
        result = _format_comment(
            [("mod_0.py", 0.9)], [], head_sha="abc",
            llm_summary="Code does many things.", behavioral_flags=flags,
        )

        assert "Behavioral Analysis" in result
        assert "**Issues:** 10" in result
        for i in range(10):
            assert f"Behavioral issue #{i}" in result

    def test_flags_with_mixed_severities(self):
        flags = [
            {"flag": "Critical risk", "severity": "high", "location": "a.py:1"},
            {"flag": "Minor risk", "severity": "low", "location": "b.py:5"},
            {"flag": "Medium risk", "severity": "medium", "location": ""},
        ]
        result = _format_comment(
            [("a.py", 0.9)], [], head_sha="abc",
            llm_summary="Summary.", behavioral_flags=flags,
        )
        assert "1 high" in result
        assert "1 low" in result
        assert "1 medium" in result
        assert "Critical risk" in result
        assert "Minor risk" in result
        assert "Medium risk" in result


class TestManyAIFiles:
    def test_15_files_all_listed(self):
        ai_files = [(f"src/components/Component{i}.tsx", 0.8) for i in range(15)]
        result = _format_comment(ai_files, [], head_sha="abc")

        assert "**AI-authored files:** 15" in result
        for i in range(15):
            assert f"Component{i}.tsx" in result

    def test_files_sorted_alphabetically(self):
        ai_files = [("z_last.py", 0.9), ("a_first.py", 0.8), ("m_middle.py", 0.7)]
        result = _format_comment(ai_files, [], head_sha="abc")
        a_pos = result.index("a_first.py")
        m_pos = result.index("m_middle.py")
        z_pos = result.index("z_last.py")
        assert a_pos < m_pos < z_pos


class TestLongMessages:
    def test_very_long_rule_messages(self):
        long_msg = "A" * 2000
        findings = [_make_finding("long-rule", "warning", message=long_msg)]
        result = _format_comment([("a.py", 0.9)], findings, head_sha="abc")
        assert long_msg in result

    def test_very_long_llm_summary(self):
        long_summary = "This code " + "does something important. " * 200
        result = _format_comment(
            [("a.py", 0.9)], [], head_sha="abc",
            llm_summary=long_summary,
        )
        assert "This code" in result


class TestSpecialCharacters:
    def test_filenames_with_dots_and_slashes(self):
        ai_files = [
            ("src/utils/api.service.ts", 0.9),
            ("src/components/my-component.test.tsx", 0.8),
        ]
        result = _format_comment(ai_files, [], head_sha="abc")
        assert "api.service.ts" in result

    def test_filenames_with_unicode(self):
        ai_files = [("src/módulo.py", 0.9)]
        result = _format_comment(ai_files, [], head_sha="abc")
        assert "módulo.py" in result

    def test_finding_message_with_special_chars(self):
        findings = [_make_finding("rule", "warning", message="Use `os.getenv()` instead of $VAR")]
        result = _format_comment([("a.py", 0.9)], findings, head_sha="abc")
        assert "`os.getenv()`" in result


class TestEmptyEdgeCases:
    def test_empty_strings_everywhere(self):
        result = _format_comment([("", 0.0)], [], head_sha="")
        assert "CodeSentry Analysis" in result
        assert "unknown" in result

    def test_no_findings_no_flags_no_summary(self):
        result = _format_comment([("a.py", 0.9)], [], head_sha="abc")
        assert "Low" in result
        assert "Issues:** 0" in result

    def test_findings_plus_flags_combined_count(self):
        findings = [_make_finding("r1", "error"), _make_finding("r2", "warning")]
        flags = [
            {"flag": "f1", "severity": "high", "location": "a.py:1"},
            {"flag": "f2", "severity": "low", "location": "a.py:5"},
            {"flag": "f3", "severity": "medium", "location": ""},
        ]
        result = _format_comment(
            [("a.py", 0.9)], findings, head_sha="abc",
            llm_summary="test", behavioral_flags=flags,
        )
        assert "**Issues:** 5" in result
