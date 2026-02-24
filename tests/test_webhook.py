"""Tests for the /webhook endpoint with mocked GitHub API calls."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.analysis.semgrep import SemgrepResult
from app.main import app

FAKE_PR_PAYLOAD = {
    "action": "opened",
    "pull_request": {
        "number": 42,
        "head": {"sha": "abc123def456"},
    },
    "repository": {"full_name": "owner/repo"},
    "installation": {"id": 12345},
}

FAKE_FILES = [
    {
        "filename": "app.py",
        "status": "added",
        "patch": "+api_key = 'sk-secret'\n",
        "raw_url": "https://raw.githubusercontent.com/owner/repo/abc/app.py",
    },
]

FAKE_COMMITS = [
    {"sha": "abc123", "message": "generated with cursor"},
]

FAKE_FINDINGS = [
    {
        "rule_id": "hardcoded-secret-string",
        "category": "security",
        "severity": "error",
        "file_path": "app.py",
        "line_start": 1,
        "message": "Hardcoded secret in `api_key`.",
    },
]

FAKE_LLM_PARSED = {
    "summary": "This code adds a hardcoded API key.",
    "behavioral_flags": [
        {"flag": "Secret exposed", "severity": "high", "location": "app.py:1"},
    ],
}


@pytest.fixture(autouse=True)
def _bypass_signature():
    """Skip HMAC verification for all tests in this module."""
    with patch("app.main.verify_signature", return_value=True):
        yield


@pytest.fixture(autouse=True)
def _mock_db_lookups():
    """Mock DB functions that are called during handle_pr_event to avoid hitting real DB."""
    with (
        patch("app.main.get_comment_id_for_pr", return_value=None),
        patch("app.main.check_rate_limit", return_value=True),
        patch("app.main.get_dismissed_rules_for_pr", return_value=set()),
        patch("app.main.save_llm_cost"),
    ):
        yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _webhook_headers(event: str = "pull_request") -> dict:
    return {
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": "sha256=unused",
    }


def _llm_mocks():
    """Return a dict of common LLM-related mock decorators."""
    return {
        "cache_llm_result": patch("app.main.cache_llm_result"),
        "get_cached": patch("app.main.get_cached_llm_result", return_value=None),
        "dedup": patch("app.main.deduplicate_flags", return_value=[]),
        "parse": patch("app.main.parse_llm_response", return_value=FAKE_LLM_PARSED),
        "claude": patch("app.main.call_claude", new_callable=AsyncMock,
                        return_value={"text": "{}"}),
        "prompt": patch("app.main.build_prompt", return_value="test prompt"),
    }


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestStatsEndpoint:
    def test_stats_returns_data(self, client):
        with patch("app.main.get_cost_stats", return_value={
            "total_analyses": 5,
            "average_cost_usd": 0.0012,
            "total_cost_usd": 0.006,
        }):
            resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_analyses"] == 5
        assert data["total_cost_usd"] == 0.006


class TestWebhookSignature:
    def test_invalid_signature_rejected(self, client):
        with patch("app.main.verify_signature", return_value=False):
            resp = client.post(
                "/webhook",
                json=FAKE_PR_PAYLOAD,
                headers=_webhook_headers(),
            )
        assert resp.status_code == 401


class TestPREventFlow:
    """Full happy-path: PR opened -> detect AI files -> semgrep -> LLM -> comment."""

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=FAKE_LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult(findings=FAKE_FINDINGS))
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_pr_opened_with_ai_files_and_findings(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )

        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        mock_token.assert_called_once_with(12345)
        mock_post.assert_called_once()
        mock_files.assert_called_once()
        mock_commits.assert_called_once()
        mock_semgrep.assert_called_once()
        mock_call_claude.assert_called_once()

        final_call = mock_edit.call_args_list[-1]
        body = final_call.args[3] if len(final_call.args) > 3 else final_call.kwargs.get("body", "")
        assert "CodeSentry Analysis" in body
        assert "hardcoded-secret-string" in body

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value={"summary": "", "behavioral_flags": []})
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value=None)
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult())
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=[{"sha": "a", "message": "fix typo"}])
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_pr_with_no_ai_files_still_runs_semgrep(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        mock_semgrep.assert_called_once()
        final_body = mock_edit.call_args_list[-1].args[3]
        assert "AI-authored files:** 0" in final_body
        assert "No issues found" in final_body

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value={"summary": "test", "behavioral_flags": []})
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="prompt")
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult())
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_ai_files_with_no_findings(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "No issues found" in final_body

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value={"summary": "", "behavioral_flags": []})
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"error": "llm_unavailable"})
    @patch("app.main.build_prompt", return_value="prompt")
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult(success=False, error="Semgrep timed out after 120s"))
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_semgrep_error_shows_in_comment(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "Static analysis error" in final_body

    @patch("app.main.get_pr_files", new_callable=AsyncMock, side_effect=Exception("API down"))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_error_during_analysis_updates_comment(
        self,
        mock_token,
        mock_post,
        mock_edit,
        mock_files,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "encountered an error" in final_body

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value={"summary": "", "behavioral_flags": []})
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"error": "llm_unavailable"})
    @patch("app.main.build_prompt", return_value="prompt")
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult(findings=FAKE_FINDINGS))
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_llm_unavailable_shows_findings_with_note(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "Behavioral summary unavailable" in final_body
        assert "hardcoded-secret-string" in final_body

    @patch("app.main.deduplicate_flags", return_value=[{"flag": "edge case", "severity": "medium", "location": "app.py:50"}])
    @patch("app.main.get_cached_llm_result", return_value={
        "summary": "Cached summary.", "flags": [{"flag": "edge case", "severity": "medium", "location": "app.py:50"}]
    })
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult(findings=FAKE_FINDINGS))
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_cache_hit_skips_claude_call(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_get_cached,
        mock_dedup,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "Cached summary." in final_body


class TestRepushEditsExistingComment:
    """Re-push (synchronize) should edit existing comment, not post a new one."""

    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value={"summary": "test", "behavioral_flags": []})
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="prompt")
    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult())
    @patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/app.py"]))
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=FAKE_COMMITS)
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_second_push_uses_edit(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        mock_write_tmp,
        mock_semgrep,
        mock_build_prompt,
        mock_call_claude,
        mock_parse,
        mock_dedup,
        mock_get_cached,
        mock_cache_llm,
        client,
    ):
        sync_payload = {**FAKE_PR_PAYLOAD, "action": "synchronize"}

        # First push: get_comment_id_for_pr returns None (autouse mock), so post_comment is called
        resp = client.post("/webhook", json=sync_payload, headers=_webhook_headers())
        assert resp.status_code == 200
        assert mock_post.call_count == 1

        first_edit_count = mock_edit.call_count

        # Second push: get_comment_id_for_pr returns 999 (the comment posted in the first push)
        with patch("app.main.get_comment_id_for_pr", return_value=999):
            resp = client.post("/webhook", json=sync_payload, headers=_webhook_headers())
        assert resp.status_code == 200

        # post_comment should still have been called only once (from the first push)
        assert mock_post.call_count == 1
        # edit_comment should have been called additional times for the second push
        assert mock_edit.call_count > first_edit_count


class TestRateLimiting:
    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_rate_limited_shows_message(
        self,
        mock_token,
        mock_post,
        mock_edit,
        client,
    ):
        with patch("app.main.check_rate_limit", return_value=False):
            resp = client.post(
                "/webhook",
                json=FAKE_PR_PAYLOAD,
                headers=_webhook_headers(),
            )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        final_body = mock_edit.call_args_list[-1].args[3]
        assert "Rate limit reached" in final_body
        assert "20 analyses/hour" in final_body


class TestDismissComment:
    """Tests for the issue_comment dismiss mechanism."""

    DISMISS_PAYLOAD = {
        "action": "created",
        "issue": {
            "number": 42,
            "pull_request": {"url": "https://api.github.com/repos/owner/repo/pulls/42"},
        },
        "comment": {
            "body": "codesentry ignore hardcoded-secret-string: it's a test key",
            "user": {"type": "User"},
        },
        "repository": {"full_name": "owner/repo"},
        "installation": {"id": 12345},
    }

    @patch("app.main.dismiss_finding", return_value=True)
    @patch("app.main.get_latest_analysis_for_pr", return_value={"id": 1, "comment_id": 999})
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=1001)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_valid_dismiss_posts_confirmation(
        self, mock_token, mock_post, mock_analysis, mock_dismiss, client,
    ):
        resp = client.post(
            "/webhook", json=self.DISMISS_PAYLOAD,
            headers=_webhook_headers("issue_comment"),
        )
        assert resp.status_code == 200

        mock_dismiss.assert_called_once_with(1, "hardcoded-secret-string", "it's a test key")
        reply_body = mock_post.call_args.args[3]
        assert "Dismissed" in reply_body
        assert "hardcoded-secret-string" in reply_body

    @patch("app.main.dismiss_finding", return_value=False)
    @patch("app.main.get_latest_analysis_for_pr", return_value={"id": 1, "comment_id": 999})
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=1001)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_unknown_rule_posts_warning(
        self, mock_token, mock_post, mock_analysis, mock_dismiss, client,
    ):
        payload = {**self.DISMISS_PAYLOAD}
        payload["comment"] = {
            "body": "codesentry ignore nonexistent-rule: reason",
            "user": {"type": "User"},
        }
        resp = client.post(
            "/webhook", json=payload,
            headers=_webhook_headers("issue_comment"),
        )
        assert resp.status_code == 200

        reply_body = mock_post.call_args.args[3]
        assert "No active finding" in reply_body

    def test_non_dismiss_comment_ignored(self, client):
        payload = {
            "action": "created",
            "issue": {
                "number": 42,
                "pull_request": {"url": "..."},
            },
            "comment": {
                "body": "LGTM!",
                "user": {"type": "User"},
            },
            "repository": {"full_name": "owner/repo"},
            "installation": {"id": 12345},
        }
        with patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token"):
            resp = client.post(
                "/webhook", json=payload,
                headers=_webhook_headers("issue_comment"),
            )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_comment_on_issue_not_pr_ignored(self, client):
        payload = {
            "action": "created",
            "issue": {"number": 10},
            "comment": {
                "body": "codesentry ignore rule: reason",
                "user": {"type": "User"},
            },
            "repository": {"full_name": "owner/repo"},
            "installation": {"id": 12345},
        }
        resp = client.post(
            "/webhook", json=payload,
            headers=_webhook_headers("issue_comment"),
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    @patch("app.main.dismiss_finding", return_value=True)
    @patch("app.main.get_latest_analysis_for_pr", return_value={"id": 1, "comment_id": 999})
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=1001)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_codesentry_colon_ignore_variant(
        self, mock_token, mock_post, mock_analysis, mock_dismiss, client,
    ):
        payload = {**self.DISMISS_PAYLOAD}
        payload["comment"] = {
            "body": "CodeSentry: ignore some-rule: my reason here",
            "user": {"type": "User"},
        }
        resp = client.post(
            "/webhook", json=payload,
            headers=_webhook_headers("issue_comment"),
        )
        assert resp.status_code == 200
        mock_dismiss.assert_called_once_with(1, "some-rule", "my reason here")

    def test_bot_comment_ignored(self, client):
        payload = {**self.DISMISS_PAYLOAD}
        payload["comment"] = {
            "body": "codesentry ignore rule: reason",
            "user": {"type": "Bot"},
        }
        resp = client.post(
            "/webhook", json=payload,
            headers=_webhook_headers("issue_comment"),
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


class TestMalformedPayloads:
    def test_missing_pull_request_key(self, client):
        payload = {
            "action": "opened",
            "repository": {"full_name": "owner/repo"},
            "installation": {"id": 12345},
        }
        resp = client.post(
            "/webhook", json=payload, headers=_webhook_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["error"] == "malformed payload"

    def test_missing_installation_key(self, client):
        payload = {
            "action": "opened",
            "pull_request": {"number": 1, "head": {"sha": "abc"}},
            "repository": {"full_name": "owner/repo"},
        }
        resp = client.post(
            "/webhook", json=payload, headers=_webhook_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["error"] == "malformed payload"


class TestNonPREvents:
    def test_non_pr_event_returns_ok(self, client):
        resp = client.post(
            "/webhook",
            json={"action": "created"},
            headers={
                "X-GitHub-Event": "issue_comment",
                "X-Hub-Signature-256": "sha256=unused",
            },
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_pr_closed_action_ignored(self, client):
        payload = {**FAKE_PR_PAYLOAD, "action": "closed"}
        resp = client.post(
            "/webhook",
            json=payload,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200
