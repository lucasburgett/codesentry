"""Stress tests: detection heuristics with realistic multi-file PR data."""

import pytest

from app.analysis.detect import detect_ai_files


def _make_file(name: str, status: str = "added", patch: str = "") -> dict:
    return {"filename": name, "status": status, "patch": patch}


class TestMultiFileCommitHeuristic:
    def test_ten_files_all_flagged(self):
        files = [_make_file(f"module_{i}.py") for i in range(10)]
        commits = [{"message": "feat: generated with cursor"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 10
        for _, confidence in result:
            assert confidence == 0.9

    def test_mixed_extensions_all_flagged(self):
        files = [
            _make_file("backend/app.py"),
            _make_file("backend/models.py"),
            _make_file("frontend/App.tsx"),
            _make_file("frontend/api.ts"),
            _make_file("frontend/utils.js"),
        ]
        commits = [{"message": "generated using copilot"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 5
        flagged_names = {name for name, _ in result}
        assert "frontend/App.tsx" in flagged_names

    def test_multiple_commit_messages_any_match_triggers(self):
        files = [_make_file("app.py"), _make_file("utils.py")]
        commits = [
            {"message": "fix: typo in readme"},
            {"message": "refactor database layer"},
            {"message": "add feature - vibe coded this one"},
        ]
        result = detect_ai_files(files, commits)

        assert len(result) == 2
        for _, conf in result:
            assert conf == 0.9


class TestMixedCleanAndAIFiles:
    def test_only_styled_files_flagged(self):
        ai_styled_patch = """\
+# Step 1: Initialize
+db = connect()
+# Step 2: Migrate
+migrate(db)
+# TODO: Add error handling
"""
        clean_patch = "+x = 1\n+y = 2\n"
        files = [
            _make_file("ai_module.py", "modified", ai_styled_patch),
            _make_file("clean_module.py", "modified", clean_patch),
            _make_file("another_clean.py", "modified", "+return True\n"),
        ]
        commits = [{"message": "refactor modules"}]
        result = detect_ai_files(files, commits)

        flagged_names = {name for name, _ in result}
        assert "ai_module.py" in flagged_names
        assert "clean_module.py" not in flagged_names
        assert "another_clean.py" not in flagged_names

    def test_multiple_ai_styled_files(self):
        patch_a = '+# Step 1: Setup\n+# Step 2: Run\n+# TODO: Add error handling\n'
        patch_b = """\
+# Import the module
+import os
+# Set the path
+path = "."
+# Create the directory
+os.makedirs(path)
"""
        files = [
            _make_file("a.py", "modified", patch_a),
            _make_file("b.py", "modified", patch_b),
            _make_file("c.py", "modified", "+pass\n"),
        ]
        commits = [{"message": "add utilities"}]
        result = detect_ai_files(files, commits)

        flagged_names = {name for name, _ in result}
        assert "a.py" in flagged_names
        assert "b.py" in flagged_names
        assert "c.py" not in flagged_names


class TestLargePR:
    def test_50_files_no_crash(self):
        files = [_make_file(f"pkg/module_{i}.py", "modified", "+x = 1\n") for i in range(50)]
        commits = [{"message": "bulk refactor"}]
        result = detect_ai_files(files, commits)
        assert isinstance(result, list)

    def test_50_files_with_commit_signal(self):
        files = [_make_file(f"pkg/module_{i}.py") for i in range(50)]
        commits = [{"message": "generated with cursor"}]
        result = detect_ai_files(files, commits)
        assert len(result) == 50


class TestNoFalsePositives:
    def test_clean_code_clean_commits(self):
        files = [
            _make_file("app.py", "modified", "+resp.raise_for_status()\n+return resp.json()\n"),
            _make_file("utils.py", "modified", "+with open('f') as fh:\n+    data = fh.read()\n"),
            _make_file("config.py", "modified", "+import os\n+key = os.getenv('KEY')\n"),
        ]
        commits = [
            {"message": "fix: handle error responses properly"},
            {"message": "refactor: use context managers for file I/O"},
        ]
        result = detect_ai_files(files, commits)
        assert result == []

    def test_short_new_files_not_flagged(self):
        patch = "\n".join([f"+line {i}" for i in range(30)])
        files = [_make_file("small_new.py", "added", patch)]
        commits = [{"message": "add small helper"}]
        result = detect_ai_files(files, commits)
        assert result == []


class TestEdgeCases:
    def test_delete_only_patch(self):
        patch = "-old line 1\n-old line 2\n-old line 3\n"
        files = [_make_file("removed.py", "modified", patch)]
        commits = [{"message": "cleanup"}]
        result = detect_ai_files(files, commits)
        assert result == []

    def test_empty_patches(self):
        files = [
            _make_file("no_patch.py", "modified", ""),
            _make_file("none_patch.py", "modified", None),
        ]
        for f in files:
            if f["patch"] is None:
                f["patch"] = None
        commits = [{"message": "minor changes"}]
        result = detect_ai_files(files, commits)
        assert isinstance(result, list)

    def test_rename_only_files(self):
        files = [
            {"filename": "new_name.py", "status": "renamed", "patch": ""},
            {"filename": "another.py", "status": "renamed", "patch": "+# minor\n"},
        ]
        commits = [{"message": "rename files"}]
        result = detect_ai_files(files, commits)
        assert isinstance(result, list)

    def test_empty_file_list(self):
        result = detect_ai_files([], [{"message": "generated with cursor"}])
        assert result == []

    def test_empty_commits_list(self):
        files = [_make_file("app.py", "modified", "+x = 1\n")]
        result = detect_ai_files(files, [])
        assert isinstance(result, list)
