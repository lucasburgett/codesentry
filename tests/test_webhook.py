"""Tests for the /webhook endpoint with mocked GitHub API calls."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

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


@pytest.fixture(autouse=True)
def _bypass_signature():
    """Skip HMAC verification for all tests in this module."""
    with patch("app.main.verify_signature", return_value=True):
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


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


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
    """Full happy-path: PR opened → detect AI files → semgrep → update comment."""

    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=FAKE_FINDINGS)
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

        # Final edit_comment should contain the finding
        final_call = mock_edit.call_args_list[-1]
        body = final_call.args[3] if len(final_call.args) > 3 else final_call.kwargs.get("body", "")
        assert "hardcoded-secret-string" in body
        assert "app.py" in body

    @patch("app.main.edit_comment", new_callable=AsyncMock)
    @patch("app.main.post_comment", new_callable=AsyncMock, return_value=999)
    @patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=[{"sha": "a", "message": "fix typo"}])
    @patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FAKE_FILES)
    @patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="fake-token")
    def test_pr_with_no_ai_files_posts_clean_message(
        self,
        mock_token,
        mock_files,
        mock_commits,
        mock_post,
        mock_edit,
        client,
    ):
        resp = client.post(
            "/webhook",
            json=FAKE_PR_PAYLOAD,
            headers=_webhook_headers(),
        )
        assert resp.status_code == 200

        edit_body = mock_edit.call_args.args[3] if mock_edit.call_args else ""
        assert "No AI-authored files detected" in edit_body

    @patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=[])
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
