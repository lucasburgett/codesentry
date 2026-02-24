"""Stress tests: LLM prompt building, parsing, and deduplication."""

import json

import pytest

from app.analysis.llm import build_prompt, deduplicate_flags, parse_llm_response


class TestBuildPromptLargeInputs:
    def test_50_files_truncates_with_message(self):
        files = [
            {"filename": f"module_{i}.py", "patch": "\n".join(f"+line {j} content" for j in range(50))}
            for i in range(50)
        ]
        result = build_prompt(files)
        assert result is not None
        assert "senior software engineer" in result
        assert "truncated" in result

    def test_one_huge_file_truncated(self):
        huge_patch = "\n".join(f"+line {i} with padding content here xxx" for i in range(10000))
        files = [{"filename": "massive.py", "patch": huge_patch}]
        result = build_prompt(files)

        assert result is not None
        assert "massive.py" in result
        assert "truncated" in result
        assert len(result) < len(huge_patch)

    def test_mixed_additions_deletions(self):
        patch = (
            "-old line 1\n"
            "-old line 2\n"
            "+new line 1\n"
            "+new line 2\n"
            "-removed\n"
            "+added\n"
        )
        files = [{"filename": "mixed.py", "patch": patch}]
        result = build_prompt(files)
        assert result is not None
        assert "mixed.py" in result

    def test_all_delete_only_returns_none(self):
        files = [
            {"filename": "a.py", "patch": "-line1\n-line2\n"},
            {"filename": "b.py", "patch": "-only deletions\n"},
        ]
        result = build_prompt(files)
        assert result is None

    def test_many_small_files_fit(self):
        files = [
            {"filename": f"small_{i}.py", "patch": f"+x = {i}\n"}
            for i in range(100)
        ]
        result = build_prompt(files)
        assert result is not None
        included_count = sum(1 for i in range(100) if f"small_{i}.py" in result)
        assert included_count >= 10


class TestParseResponseMalformedVariants:
    def test_trailing_comma_in_json(self):
        raw = '{"summary": "test", "behavioral_flags": [{"flag": "x", "severity": "low", "location": "a:1"},]}'
        result = parse_llm_response(raw)
        assert isinstance(result["summary"], str)
        assert isinstance(result["behavioral_flags"], list)

    def test_missing_closing_brace(self):
        raw = '{"summary": "test", "behavioral_flags": []'
        result = parse_llm_response(raw)
        assert isinstance(result["summary"], str)

    def test_nested_json_error(self):
        raw = '{"summary": "test", "behavioral_flags": [{"flag": {}}]}'
        result = parse_llm_response(raw)
        assert isinstance(result["behavioral_flags"], list)

    def test_json_with_extra_text_before(self):
        raw = 'Here is my analysis:\n\n{"summary": "test code", "behavioral_flags": []}'
        result = parse_llm_response(raw)
        assert result["summary"] == "test code"

    def test_json_with_markdown_and_extra_text(self):
        inner = json.dumps({"summary": "works", "behavioral_flags": [
            {"flag": "risk A", "severity": "high", "location": "f.py:1"},
        ]})
        raw = f"Sure! Here's the analysis:\n\n```json\n{inner}\n```\n\nLet me know if you need more."
        result = parse_llm_response(raw)
        assert result["summary"] == "works"
        assert len(result["behavioral_flags"]) == 1

    def test_completely_empty_string(self):
        result = parse_llm_response("")
        assert result["summary"] == ""
        assert result["behavioral_flags"] == []

    def test_html_response(self):
        raw = "<html><body>Error 500</body></html>"
        result = parse_llm_response(raw)
        assert isinstance(result["summary"], str)
        assert result["behavioral_flags"] == []

    def test_flags_with_missing_fields(self):
        raw = json.dumps({
            "summary": "ok",
            "behavioral_flags": [
                {"flag": "only flag"},
                {"severity": "high"},
                {},
            ],
        })
        result = parse_llm_response(raw)
        assert len(result["behavioral_flags"]) == 3
        assert result["behavioral_flags"][0]["flag"] == "only flag"
        assert result["behavioral_flags"][0]["severity"] == "medium"
        assert result["behavioral_flags"][1]["flag"] == ""


class TestDeduplicateWithManyOverlaps:
    def test_15_of_20_flags_overlap(self):
        llm_flags = [
            {"flag": f"Issue #{i}", "severity": "medium", "location": f"app.py:{i * 10}"}
            for i in range(20)
        ]
        semgrep_findings = [
            {
                "rule_id": f"rule-{i}",
                "file_path": "app.py",
                "line_start": i * 10 + 1,
                "category": "security",
                "severity": "error",
                "message": "msg",
            }
            for i in range(15)
        ]
        result = deduplicate_flags(llm_flags, semgrep_findings)
        assert len(result) == 5
        remaining_indices = {int(f["flag"].split("#")[1]) for f in result}
        assert remaining_indices == {15, 16, 17, 18, 19}

    def test_no_overlaps_all_kept(self):
        llm_flags = [
            {"flag": f"Issue #{i}", "severity": "low", "location": f"utils.py:{i}"}
            for i in range(10)
        ]
        semgrep_findings = [
            {
                "rule_id": "rule",
                "file_path": "other_file.py",
                "line_start": 1,
                "category": "security",
                "severity": "error",
                "message": "msg",
            }
        ]
        result = deduplicate_flags(llm_flags, semgrep_findings)
        assert len(result) == 10

    def test_same_line_different_files_kept(self):
        llm_flags = [
            {"flag": "risk", "severity": "high", "location": "a.py:10"},
        ]
        semgrep_findings = [
            {"rule_id": "r", "file_path": "b.py", "line_start": 10,
             "category": "c", "severity": "e", "message": "m"},
        ]
        result = deduplicate_flags(llm_flags, semgrep_findings)
        assert len(result) == 1
