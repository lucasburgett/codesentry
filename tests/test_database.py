"""Tests for database operations."""

import os
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app.db.database import (
    cache_llm_result,
    check_rate_limit,
    create_analysis,
    create_finding,
    dismiss_finding,
    get_active_findings,
    get_cached_llm_result,
    get_comment_id_for_pr,
    get_cost_stats,
    get_dismissed_rules_for_pr,
    get_latest_analysis_for_pr,
    init_db,
    save_llm_cost,
    update_analysis_status,
    _connect,
)


@pytest.fixture(autouse=True)
def _use_temp_db(monkeypatch):
    """Use a temporary database file for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("DATABASE_PATH", path)
    import app.db.database as db_mod
    monkeypatch.setattr(db_mod, "DATABASE_PATH", path)
    init_db()
    yield path
    os.unlink(path)


class TestCreateAnalysis:
    def test_returns_id(self):
        aid = create_analysis(
            installation_id=1,
            repo_full_name="owner/repo",
            pr_number=42,
            pr_head_sha="abc123",
            comment_id=999,
            status="pending",
        )
        assert isinstance(aid, int)
        assert aid > 0

    def test_sequential_ids(self):
        aid1 = create_analysis(1, "owner/repo", 1, "sha1", None, "pending")
        aid2 = create_analysis(1, "owner/repo", 2, "sha2", None, "pending")
        assert aid2 == aid1 + 1


class TestCreateFinding:
    def test_returns_id(self):
        aid = create_analysis(1, "owner/repo", 1, "sha", None, "complete")
        fid = create_finding(
            analysis_id=aid,
            rule_id="hardcoded-secret",
            category="security",
            severity="error",
            file_path="app.py",
            line_start=3,
            message="test finding",
        )
        assert isinstance(fid, int)
        assert fid > 0

    def test_multiple_findings(self):
        aid = create_analysis(1, "owner/repo", 1, "sha", None, "complete")
        ids = []
        for i in range(5):
            fid = create_finding(aid, f"rule-{i}", "security", "error", "f.py", i, "msg")
            ids.append(fid)
        assert len(set(ids)) == 5


class TestUpdateAnalysisStatus:
    def test_updates_status(self):
        aid = create_analysis(1, "owner/repo", 1, "sha", None, "pending")
        update_analysis_status(aid, "complete")

        conn = _connect()
        row = conn.execute("SELECT status FROM analyses WHERE id = ?", (aid,)).fetchone()
        conn.close()
        assert row["status"] == "complete"

    def test_update_to_error(self):
        aid = create_analysis(1, "owner/repo", 1, "sha", None, "pending")
        update_analysis_status(aid, "error")

        conn = _connect()
        row = conn.execute("SELECT status FROM analyses WHERE id = ?", (aid,)).fetchone()
        conn.close()
        assert row["status"] == "error"


class TestCacheLlmResult:
    def test_cache_and_retrieve(self):
        create_analysis(1, "owner/repo", 1, "sha-abc", None, "complete")
        cache_llm_result("sha-abc", "This adds auth.", '[{"flag": "no rate limit"}]')

        result = get_cached_llm_result("sha-abc")
        assert result is not None
        assert result["summary"] == "This adds auth."
        assert len(result["flags"]) == 1
        assert result["flags"][0]["flag"] == "no rate limit"

    def test_cache_miss_returns_none(self):
        assert get_cached_llm_result("nonexistent-sha") is None

    def test_uncached_analysis_returns_none(self):
        create_analysis(1, "owner/repo", 1, "sha-xyz", None, "complete")
        assert get_cached_llm_result("sha-xyz") is None

    def test_cache_updates_most_recent(self):
        create_analysis(1, "owner/repo", 1, "sha-dup", None, "complete")
        create_analysis(1, "owner/repo", 2, "sha-dup", None, "complete")
        cache_llm_result("sha-dup", "second analysis", "[]")

        result = get_cached_llm_result("sha-dup")
        assert result["summary"] == "second analysis"

    def test_invalid_json_flags_returns_empty_list(self):
        aid = create_analysis(1, "owner/repo", 1, "sha-bad", None, "complete")
        conn = _connect()
        conn.execute(
            "UPDATE analyses SET llm_summary = ?, llm_flags = ? WHERE id = ?",
            ("summary", "not valid json", aid),
        )
        conn.commit()
        conn.close()

        result = get_cached_llm_result("sha-bad")
        assert result is not None
        assert result["summary"] == "summary"
        assert result["flags"] == []

    def test_null_flags_returns_empty_list(self):
        aid = create_analysis(1, "owner/repo", 1, "sha-null", None, "complete")
        conn = _connect()
        conn.execute(
            "UPDATE analyses SET llm_summary = ? WHERE id = ?",
            ("summary", aid),
        )
        conn.commit()
        conn.close()

        result = get_cached_llm_result("sha-null")
        assert result is not None
        assert result["flags"] == []


class TestDismissFinding:
    def test_dismiss_existing_finding(self):
        aid = create_analysis(1, "owner/repo", 1, "sha1", 999, "complete")
        create_finding(aid, "hardcoded-secret", "security", "error", "app.py", 3, "secret")

        result = dismiss_finding(aid, "hardcoded-secret", "it's a test key")
        assert result is True

        active = get_active_findings(aid)
        assert len(active) == 0

    def test_dismiss_nonexistent_rule_returns_false(self):
        aid = create_analysis(1, "owner/repo", 1, "sha2", 999, "complete")
        create_finding(aid, "real-rule", "security", "error", "app.py", 1, "msg")

        result = dismiss_finding(aid, "nonexistent-rule", "reason")
        assert result is False

        active = get_active_findings(aid)
        assert len(active) == 1

    def test_get_active_findings_excludes_dismissed(self):
        aid = create_analysis(1, "owner/repo", 1, "sha3", 999, "complete")
        create_finding(aid, "rule-a", "security", "error", "a.py", 1, "msg")
        create_finding(aid, "rule-b", "quality", "warning", "b.py", 5, "msg")

        dismiss_finding(aid, "rule-a", "reason")

        active = get_active_findings(aid)
        assert len(active) == 1
        assert active[0]["rule_id"] == "rule-b"

    def test_get_dismissed_rules_for_pr(self):
        aid = create_analysis(1, "owner/repo", 42, "sha4", 999, "complete")
        create_finding(aid, "rule-x", "security", "error", "x.py", 1, "msg")
        dismiss_finding(aid, "rule-x", "reason")

        dismissed = get_dismissed_rules_for_pr("owner/repo", 42)
        assert "rule-x" in dismissed

    def test_get_dismissed_rules_empty_when_no_dismissals(self):
        create_analysis(1, "owner/repo", 43, "sha5", 999, "complete")
        dismissed = get_dismissed_rules_for_pr("owner/repo", 43)
        assert dismissed == set()


class TestGetLatestAnalysisForPr:
    def test_returns_latest(self):
        create_analysis(1, "owner/repo", 10, "sha-old", 100, "complete")
        create_analysis(1, "owner/repo", 10, "sha-new", 200, "complete")

        result = get_latest_analysis_for_pr("owner/repo", 10)
        assert result is not None
        assert result["comment_id"] == 200
        assert result["pr_head_sha"] == "sha-new"

    def test_returns_none_for_unknown_pr(self):
        result = get_latest_analysis_for_pr("owner/repo", 9999)
        assert result is None


class TestGetCommentIdForPr:
    def test_returns_comment_id(self):
        create_analysis(1, "owner/repo", 20, "sha-a", 555, "complete")
        assert get_comment_id_for_pr("owner/repo", 20) == 555

    def test_returns_none_for_unknown(self):
        assert get_comment_id_for_pr("owner/repo", 9999) is None

    def test_returns_none_when_comment_id_is_null(self):
        create_analysis(1, "owner/repo", 21, "sha-b", None, "error")
        assert get_comment_id_for_pr("owner/repo", 21) is None


class TestRateLimiting:
    def test_first_call_allowed(self):
        assert check_rate_limit(9001) is True

    def test_under_limit_allowed(self):
        for _ in range(19):
            check_rate_limit(9002)
        assert check_rate_limit(9002) is True

    def test_at_limit_blocked(self):
        for _ in range(20):
            check_rate_limit(9003)
        assert check_rate_limit(9003) is False

    def test_expired_window_resets(self):
        for _ in range(20):
            check_rate_limit(9004)

        conn = _connect()
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute(
            "UPDATE rate_limits SET window_start = ? WHERE installation_id = ?",
            (past, 9004),
        )
        conn.commit()
        conn.close()

        assert check_rate_limit(9004) is True


class TestCostStats:
    def test_save_and_retrieve_cost(self):
        aid = create_analysis(1, "owner/repo", 30, "sha-cost", 999, "complete")
        save_llm_cost(aid, 100, 50, 0.0028)

        stats = get_cost_stats()
        assert stats["total_analyses"] >= 1
        assert stats["total_cost_usd"] >= 0.0028

    def test_average_cost_across_analyses(self):
        aid1 = create_analysis(1, "owner/repo", 31, "sha-c1", 100, "complete")
        aid2 = create_analysis(1, "owner/repo", 32, "sha-c2", 101, "complete")
        save_llm_cost(aid1, 100, 50, 0.002)
        save_llm_cost(aid2, 200, 100, 0.004)

        stats = get_cost_stats()
        assert stats["total_analyses"] >= 2

    def test_empty_db_returns_zero(self):
        stats = get_cost_stats()
        assert stats["total_cost_usd"] == 0
        assert stats["average_cost_usd"] == 0
