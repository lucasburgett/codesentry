"""Tests for LLM behavioral summary functions."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.analysis.llm import (
    build_prompt,
    call_claude,
    deduplicate_flags,
    filter_flags_by_evidence,
    parse_llm_response,
)


class TestParseResponse:
    def test_valid_json(self):
        raw = json.dumps({
            "summary": "This code adds a new endpoint.",
            "behavioral_flags": [
                {"flag": "No auth check", "severity": "high", "location": "app.py:10"}
            ],
        })
        result = parse_llm_response(raw)
        assert result["summary"] == "This code adds a new endpoint."
        assert len(result["behavioral_flags"]) == 1
        assert result["behavioral_flags"][0]["severity"] == "high"

    def test_json_in_markdown_code_block(self):
        inner = json.dumps({
            "summary": "Adds user login flow.",
            "behavioral_flags": [],
        })
        raw = f"```json\n{inner}\n```"
        result = parse_llm_response(raw)
        assert result["summary"] == "Adds user login flow."
        assert result["behavioral_flags"] == []

    def test_invalid_response_fallback(self):
        raw = "This is not JSON at all, just a plain text response."
        result = parse_llm_response(raw)
        assert "not JSON" in result["summary"]
        assert result["behavioral_flags"] == []

    def test_missing_keys_use_defaults(self):
        raw = json.dumps({"other_key": "value"})
        result = parse_llm_response(raw)
        assert result["summary"] == ""
        assert result["behavioral_flags"] == []

    def test_behavioral_flags_not_a_list(self):
        raw = json.dumps({"summary": "ok", "behavioral_flags": "not a list"})
        result = parse_llm_response(raw)
        assert result["summary"] == "ok"
        assert result["behavioral_flags"] == []

    def test_normalizes_flag_fields(self):
        raw = json.dumps({
            "summary": "test",
            "behavioral_flags": [
                {"flag": "risk", "severity": "low"},
            ],
        })
        result = parse_llm_response(raw)
        flag = result["behavioral_flags"][0]
        assert flag["flag"] == "risk"
        assert flag["severity"] == "low"
        assert flag["location"] == ""


class TestDeduplicateFlags:
    def test_removes_overlapping_finding(self):
        llm_flags = [
            {"flag": "Hardcoded key", "severity": "high", "location": "app.py:5"},
            {"flag": "Missing timeout", "severity": "medium", "location": "app.py:20"},
        ]
        semgrep_findings = [
            {"rule_id": "hardcoded-secret", "file_path": "app.py", "line_start": 6,
             "category": "security", "severity": "error", "message": "secret"},
        ]
        result = deduplicate_flags(llm_flags, semgrep_findings)
        assert len(result) == 1
        assert result[0]["flag"] == "Missing timeout"

    def test_keeps_non_overlapping(self):
        llm_flags = [
            {"flag": "No retry", "severity": "medium", "location": "utils.py:50"},
        ]
        semgrep_findings = [
            {"rule_id": "r1", "file_path": "app.py", "line_start": 10,
             "category": "security", "severity": "error", "message": "msg"},
        ]
        result = deduplicate_flags(llm_flags, semgrep_findings)
        assert len(result) == 1

    def test_unparseable_location_kept(self):
        llm_flags = [
            {"flag": "General risk", "severity": "medium", "location": "no-line-here"},
            {"flag": "Another", "severity": "low"},
        ]
        result = deduplicate_flags(llm_flags, [
            {"rule_id": "r1", "file_path": "app.py", "line_start": 1,
             "category": "security", "severity": "error", "message": "msg"},
        ])
        assert len(result) == 2

    def test_empty_inputs(self):
        assert deduplicate_flags([], []) == []
        assert deduplicate_flags([], [{"rule_id": "r", "file_path": "f", "line_start": 1}]) == []

    def test_within_three_lines(self):
        llm_flags = [
            {"flag": "edge", "severity": "low", "location": "f.py:10"},
        ]
        assert len(deduplicate_flags(llm_flags, [
            {"rule_id": "r", "file_path": "f.py", "line_start": 13,
             "category": "c", "severity": "w", "message": "m"},
        ])) == 0

        assert len(deduplicate_flags(llm_flags, [
            {"rule_id": "r", "file_path": "f.py", "line_start": 14,
             "category": "c", "severity": "w", "message": "m"},
        ])) == 1


class TestCallClaude:
    @pytest.mark.asyncio
    async def test_missing_api_key_raises_valueerror(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                await call_claude("test prompt")

    @pytest.mark.asyncio
    async def test_empty_api_key_raises_valueerror(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "  "}):
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                await call_claude("test prompt")

    @pytest.mark.asyncio
    async def test_successful_call(self):
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"summary": "test", "behavioral_flags": []}')]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}):
            with patch("app.analysis.llm.anthropic.AsyncAnthropic", return_value=mock_client):
                result = await call_claude("test prompt")

        assert result["text"] == '{"summary": "test", "behavioral_flags": []}'

    @pytest.mark.asyncio
    async def test_api_error_returns_unavailable(self):
        import anthropic as anth

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=anth.APIError(
                message="Server error",
                request=MagicMock(),
                body=None,
            )
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}):
            with patch("app.analysis.llm.anthropic.AsyncAnthropic", return_value=mock_client):
                result = await call_claude("test prompt")

        assert result == {"error": "llm_unavailable"}

    @pytest.mark.asyncio
    async def test_rate_limit_retries_then_fails(self):
        import anthropic as anth

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=anth.RateLimitError(
                message="Rate limited",
                response=MagicMock(status_code=429, headers={}),
                body=None,
            )
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}):
            with patch("app.analysis.llm.anthropic.AsyncAnthropic", return_value=mock_client):
                with patch("app.analysis.llm.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                    result = await call_claude("test prompt")

        assert result == {"error": "llm_unavailable"}
        assert mock_client.messages.create.call_count == 2
        mock_sleep.assert_called_once_with(2)

    @pytest.mark.asyncio
    async def test_rate_limit_succeeds_on_retry(self):
        import anthropic as anth

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"summary": "ok"}')]
        mock_response.usage.input_tokens = 50
        mock_response.usage.output_tokens = 20

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=[
                anth.RateLimitError(
                    message="Rate limited",
                    response=MagicMock(status_code=429, headers={}),
                    body=None,
                ),
                mock_response,
            ]
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}):
            with patch("app.analysis.llm.anthropic.AsyncAnthropic", return_value=mock_client):
                with patch("app.analysis.llm.asyncio.sleep", new_callable=AsyncMock):
                    result = await call_claude("test prompt")

        assert "text" in result
        assert result["text"] == '{"summary": "ok"}'

    @pytest.mark.asyncio
    async def test_empty_response_content(self):
        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage.input_tokens = 50
        mock_response.usage.output_tokens = 0

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}):
            with patch("app.analysis.llm.anthropic.AsyncAnthropic", return_value=mock_client):
                result = await call_claude("test prompt")

        assert result == {"error": "llm_unavailable"}


class TestFilterFlagsByEvidence:
    """Evidence-based gating of LLM behavioral flags."""

    SAMPLE_FLAGS = [
        {"flag": "SQL injection risk", "severity": "high", "location": "db.py:10"},
        {"flag": "Missing input validation", "severity": "medium", "location": "api.py:20"},
        {"flag": "No logging", "severity": "low", "location": "api.py:30"},
    ]

    ERROR_FINDING = [
        {"rule_id": "r1", "severity": "error", "file_path": "db.py",
         "line_start": 5, "category": "security", "message": "sql injection"},
    ]

    WARNING_FINDING = [
        {"rule_id": "r2", "severity": "warning", "file_path": "api.py",
         "line_start": 15, "category": "quality", "message": "warn"},
    ]

    INFO_FINDING = [
        {"rule_id": "r3", "severity": "info", "file_path": "api.py",
         "line_start": 25, "category": "quality", "message": "info note"},
    ]

    def test_zero_findings_keeps_only_high(self):
        result = filter_flags_by_evidence(self.SAMPLE_FLAGS, [])
        assert all(f["severity"] == "high" for f in result) or result == []

    def test_zero_findings_suppresses_if_fewer_than_two_high(self):
        result = filter_flags_by_evidence(self.SAMPLE_FLAGS, [])
        assert result == []  # only 1 high flag, below minimum threshold of 2

    def test_zero_findings_with_two_high_flags_keeps_them(self):
        flags = [
            {"flag": "A", "severity": "high", "location": "a.py:1"},
            {"flag": "B", "severity": "high", "location": "b.py:2"},
            {"flag": "C", "severity": "low", "location": "c.py:3"},
        ]
        result = filter_flags_by_evidence(flags, [])
        assert len(result) == 2
        assert all(f["severity"] == "high" for f in result)

    def test_warnings_only_keeps_high_and_medium(self):
        result = filter_flags_by_evidence(self.SAMPLE_FLAGS, self.WARNING_FINDING)
        severities = {f["severity"] for f in result}
        assert "low" not in severities
        assert len(result) == 2  # high + medium

    def test_info_only_treated_as_no_errors(self):
        result = filter_flags_by_evidence(self.SAMPLE_FLAGS, self.INFO_FINDING)
        severities = {f["severity"] for f in result}
        assert "low" not in severities
        assert len(result) == 2

    def test_errors_keep_all_flags(self):
        result = filter_flags_by_evidence(self.SAMPLE_FLAGS, self.ERROR_FINDING)
        assert len(result) == 3

    def test_minimum_threshold_suppresses_single_flag(self):
        flags = [{"flag": "X", "severity": "high", "location": "x.py:1"}]
        result = filter_flags_by_evidence(flags, self.ERROR_FINDING)
        assert result == []  # only 1 flag, below minimum of 2

    def test_empty_flags_returns_empty(self):
        assert filter_flags_by_evidence([], self.ERROR_FINDING) == []

    def test_none_equivalent_empty_list(self):
        assert filter_flags_by_evidence([], []) == []


class TestBuildPrompt:
    def test_returns_none_for_empty_files(self):
        assert build_prompt([]) is None

    def test_returns_none_for_delete_only(self):
        files = [{"filename": "app.py", "patch": "-old line\n-another"}]
        assert build_prompt(files) is None

    def test_returns_prompt_with_additions(self):
        files = [{"filename": "app.py", "patch": "+new line\n+def hello(): pass"}]
        result = build_prompt(files)
        assert result is not None
        assert "app.py" in result
        assert "new line" in result
        assert "senior software engineer" in result

    def test_skips_files_with_no_patch(self):
        files = [
            {"filename": "empty.py", "patch": ""},
            {"filename": "none.py", "patch": None},
            {"filename": "good.py", "patch": "+code here"},
        ]
        result = build_prompt(files)
        assert result is not None
        assert "good.py" in result
        assert "empty.py" not in result

    def test_truncates_large_diff(self):
        big_patch = "\n".join(f"+line {i} with some content padding here" for i in range(2000))
        files = [{"filename": "big.py", "patch": big_patch}]
        result = build_prompt(files)
        assert result is not None
        assert "truncated" in result
