"""Tests for database operations."""

import os
import tempfile

import pytest

from app.db.database import (
    create_analysis,
    create_finding,
    init_db,
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
