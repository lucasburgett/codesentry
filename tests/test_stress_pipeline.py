"""Stress tests: full pipeline via TestClient with real detection logic."""

import os
import shutil
import tempfile
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.analysis.semgrep import SemgrepResult
from app.main import app


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture_file(rel_path: str) -> str:
    with open(os.path.join(FIXTURES, rel_path)) as f:
        return f.read()


def _make_pr_file(fixture_rel_path: str, status: str = "added") -> dict:
    content = _read_fixture_file(fixture_rel_path)
    patch_lines = "\n".join(f"+{line}" for line in content.splitlines())
    return {
        "filename": fixture_rel_path.split("/", 1)[-1] if "/" in fixture_rel_path else fixture_rel_path,
        "status": status,
        "patch": patch_lines,
        "raw_url": f"https://raw.example.com/{fixture_rel_path}",
    }


FLASK_FILES = [
    _make_pr_file("vibe_flask_app/app.py"),
    _make_pr_file("vibe_flask_app/config.py"),
    _make_pr_file("vibe_flask_app/auth.py"),
    _make_pr_file("vibe_flask_app/models.py"),
    _make_pr_file("vibe_flask_app/utils.py"),
]

REACT_FILES = [
    _make_pr_file("vibe_react_app/App.tsx"),
    _make_pr_file("vibe_react_app/api.ts"),
    _make_pr_file("vibe_react_app/UserList.tsx"),
    _make_pr_file("vibe_react_app/DataFetcher.ts"),
    _make_pr_file("vibe_react_app/config.ts"),
]

CLEAN_FILES = [
    _make_pr_file("clean_app/clean_api.py"),
    _make_pr_file("clean_app/clean_component.tsx"),
]

AI_COMMITS = [{"sha": "abc123", "message": "feat: generated with cursor"}]
CLEAN_COMMITS = [{"sha": "def456", "message": "fix: improve error handling"}]

PAYLOAD_TEMPLATE = {
    "action": "opened",
    "pull_request": {"number": 99, "head": {"sha": "stress123abc"}},
    "repository": {"full_name": "test/stress-repo"},
    "installation": {"id": 99999},
}


def _webhook_headers():
    return {
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": "sha256=unused",
    }


def _semgrep_from_fixtures(fixture_dir: str):
    """Create a real SemgrepResult by running Semgrep against fixture files."""
    import asyncio
    from app.analysis.semgrep import run_semgrep

    tmp = tempfile.mkdtemp(prefix="codesentry-pipe-")
    src = os.path.join(FIXTURES, fixture_dir)
    paths = []
    for root, _, files in os.walk(src):
        for fname in files:
            if fname.startswith(".") or fname.endswith("__init__.py"):
                continue
            src_path = os.path.join(root, fname)
            rel = os.path.relpath(src_path, FIXTURES)
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src_path, dst)
            paths.append(dst)

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(run_semgrep(paths, tmp))
    finally:
        loop.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return result


@pytest.fixture(autouse=True)
def _bypass_signature():
    with patch("app.main.verify_signature", return_value=True):
        yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


LLM_PARSED = {"summary": "test summary", "behavioral_flags": []}


class TestFlaskAppPipeline:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    def test_full_pipeline_detects_issues(self, _p, _c, _pr, _d, _gc, _cl, client):
        semgrep_result = _semgrep_from_fixtures("vibe_flask_app")

        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FLASK_FILES),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=AI_COMMITS),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock) as mock_edit,
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/a.py"])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=semgrep_result),
        ):
            resp = client.post("/webhook", json=PAYLOAD_TEMPLATE, headers=_webhook_headers())

        assert resp.status_code == 200
        final_body = mock_edit.call_args_list[-1].args[3]
        assert "CodeSentry Analysis" in final_body
        assert "High" in final_body
        assert "hardcoded-secret-string" in final_body


class TestReactAppPipeline:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    def test_full_pipeline_detects_issues(self, _p, _c, _pr, _d, _gc, _cl, client):
        semgrep_result = _semgrep_from_fixtures("vibe_react_app")

        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=REACT_FILES),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=AI_COMMITS),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock) as mock_edit,
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", ["/tmp/x/a.tsx"])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=semgrep_result),
        ):
            resp = client.post("/webhook", json=PAYLOAD_TEMPLATE, headers=_webhook_headers())

        assert resp.status_code == 200
        final_body = mock_edit.call_args_list[-1].args[3]
        assert "CodeSentry Analysis" in final_body


class TestMixedPRPipeline:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    def test_both_languages_in_one_pr(self, _p, _c, _pr, _d, _gc, _cl, client):
        flask_result = _semgrep_from_fixtures("vibe_flask_app")
        react_result = _semgrep_from_fixtures("vibe_react_app")
        combined = SemgrepResult(findings=flask_result.findings + react_result.findings)

        all_files = FLASK_FILES + REACT_FILES

        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=all_files),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=AI_COMMITS),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock) as mock_edit,
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", [])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=combined),
        ):
            resp = client.post("/webhook", json=PAYLOAD_TEMPLATE, headers=_webhook_headers())

        assert resp.status_code == 200
        final_body = mock_edit.call_args_list[-1].args[3]
        rule_ids_in_comment = set()
        for f in combined.findings:
            if f["rule_id"] in final_body:
                rule_ids_in_comment.add(f["rule_id"])
        assert len(rule_ids_in_comment) >= 5


class TestCleanPRPipeline:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value=None)
    def test_clean_files_with_clean_commits(self, _p, _c, _pr, _d, _gc, _cl, client):
        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=CLEAN_FILES),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=CLEAN_COMMITS),
            patch("app.main.detect_ai_files", return_value=[]),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock) as mock_edit,
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", [])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult()),
        ):
            resp = client.post("/webhook", json=PAYLOAD_TEMPLATE, headers=_webhook_headers())

        assert resp.status_code == 200
        final_body = mock_edit.call_args_list[-1].args[3]
        assert "AI-authored files:** 0" in final_body
        assert "No issues found" in final_body


class TestLargePRTruncation:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    def test_50_file_pr_handled(self, _p, _c, _pr, _d, _gc, _cl, client):
        large_files = []
        for i in range(50):
            large_files.append({
                "filename": f"pkg/module_{i}.py",
                "status": "added",
                "patch": "\n".join(f"+line {j}" for j in range(20)),
                "raw_url": f"https://raw.example.com/module_{i}.py",
            })

        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=large_files),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=AI_COMMITS),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock) as mock_edit,
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", [])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult()),
        ):
            resp = client.post("/webhook", json=PAYLOAD_TEMPLATE, headers=_webhook_headers())

        assert resp.status_code == 200
        final_body = mock_edit.call_args_list[-1].args[3]
        assert "**AI-authored files:** 50" in final_body


class TestConcurrentWebhooks:
    @patch("app.main.cache_llm_result")
    @patch("app.main.get_cached_llm_result", return_value=None)
    @patch("app.main.deduplicate_flags", return_value=[])
    @patch("app.main.parse_llm_response", return_value=LLM_PARSED)
    @patch("app.main.call_claude", new_callable=AsyncMock, return_value={"text": "{}"})
    @patch("app.main.build_prompt", return_value="test prompt")
    def test_two_simultaneous_webhooks(self, _p, _c, _pr, _d, _gc, _cl, client):
        payload_a = {**PAYLOAD_TEMPLATE, "pull_request": {"number": 1, "head": {"sha": "aaa"}}}
        payload_b = {**PAYLOAD_TEMPLATE, "pull_request": {"number": 2, "head": {"sha": "bbb"}}}

        with (
            patch("app.main.get_installation_token", new_callable=AsyncMock, return_value="t"),
            patch("app.main.get_pr_files", new_callable=AsyncMock, return_value=FLASK_FILES[:1]),
            patch("app.main.get_pr_commits", new_callable=AsyncMock, return_value=AI_COMMITS),
            patch("app.main.post_comment", new_callable=AsyncMock, return_value=1),
            patch("app.main.edit_comment", new_callable=AsyncMock),
            patch("app.main.write_diff_to_tmp", new_callable=AsyncMock, return_value=("/tmp/x", [])),
            patch("app.main.run_semgrep", new_callable=AsyncMock, return_value=SemgrepResult()),
        ):
            resp_a = client.post("/webhook", json=payload_a, headers=_webhook_headers())
            resp_b = client.post("/webhook", json=payload_b, headers=_webhook_headers())

        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
