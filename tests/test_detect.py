"""Tests for AI-authored file detection heuristics."""

import pytest

from app.analysis.detect import detect_ai_files


class TestCommitMessageHeuristic:
    """Heuristic 1: commit message patterns flag ALL files with 0.9."""

    def test_generated_with_cursor(self):
        files = [
            {"filename": "app.py", "status": "modified", "patch": ""},
            {"filename": "utils.py", "status": "added", "patch": ""},
        ]
        commits = [{"message": "feat: generated with cursor"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 2
        for name, confidence in result:
            assert confidence == 0.9

    def test_copilot_co_authored_by(self):
        files = [{"filename": "main.py", "status": "modified", "patch": ""}]
        commits = [{"message": "fix: stuff\n\nCo-authored-by: copilot"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 1
        assert result[0][1] == 0.9

    def test_ai_generated_tag(self):
        files = [{"filename": "a.py", "status": "added", "patch": ""}]
        result = detect_ai_files(files, ["ai-generated code cleanup"])
        assert len(result) == 1

    def test_vibe_coding(self):
        files = [{"filename": "a.py", "status": "added", "patch": ""}]
        result = detect_ai_files(files, [{"message": "vibe coding session"}])
        assert len(result) == 1

    def test_aider_detected(self):
        files = [{"filename": "a.py", "status": "added", "patch": ""}]
        result = detect_ai_files(files, ["generated with aider"])
        assert len(result) == 1

    def test_windsurf_detected(self):
        files = [{"filename": "a.py", "status": "added", "patch": ""}]
        result = detect_ai_files(files, [{"message": "generated using windsurf"}])
        assert len(result) == 1

    def test_devin_co_authored(self):
        files = [{"filename": "a.py", "status": "added", "patch": ""}]
        result = detect_ai_files(files, [{"message": "fix\n\nCo-authored-by: devin"}])
        assert len(result) == 1

    def test_clean_commit_no_flag(self):
        files = [{"filename": "app.py", "status": "modified", "patch": ""}]
        commits = [{"message": "fix: correct typo in readme"}]
        result = detect_ai_files(files, commits)
        assert result == []


class TestCodeStyleHeuristic:
    """Heuristic 2: code style signals, 0.15 each, cap 0.6."""

    def test_step_comments_and_todo_flagged(self):
        """Two signals (0.15+0.15=0.30) now meets the 0.3 threshold."""
        patch = """\
+# Step 1: Initialize the database
+db = connect()
+# Step 2: Run migrations
+migrate(db)
+# TODO: Add error handling
"""
        files = [{"filename": "setup.py", "status": "modified", "patch": patch}]
        commits = [{"message": "refactor db setup"}]
        result = detect_ai_files(files, commits)
        assert len(result) == 1
        assert result[0][1] == 0.3

    def test_step_comments_plus_todo_plus_docstrings(self):
        patch = """\
+def connect(host: str, port: int):
+    \"\"\"Connect to the database.\"\"\"
+    # Step 1: validate args
+    # TODO: Add error handling
+    pass
"""
        files = [{"filename": "db.py", "status": "modified", "patch": patch}]
        commits = [{"message": "add db module"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 1
        _, confidence = result[0]
        assert confidence >= 0.45

    def test_clean_code_no_flag(self):
        patch = "+x = 1\n+y = 2\n+print(x + y)\n"
        files = [{"filename": "calc.py", "status": "modified", "patch": patch}]
        commits = [{"message": "add calculator"}]
        result = detect_ai_files(files, commits)
        assert result == []

    def test_excessive_trivial_comments(self):
        patch = """\
+# Import the module
+import os
+# Set the path
+path = "."
+# Create the directory
+os.makedirs(path)
"""
        files = [{"filename": "setup.py", "status": "modified", "patch": patch}]
        commits = [{"message": "add setup"}]
        result = detect_ai_files(files, commits)
        assert len(result) == 1


class TestFileLevelHeuristic:
    """Heuristic 3: large files get scored."""

    def test_large_new_file_flagged(self):
        patch = "\n".join([f"+line {i}" for i in range(120)])
        files = [{"filename": "big.py", "status": "added", "patch": patch}]
        commits = [{"message": "add big module"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 1
        assert result[0][1] == 0.4

    def test_small_new_file_not_flagged(self):
        patch = "\n".join([f"+line {i}" for i in range(20)])
        files = [{"filename": "tiny.py", "status": "added", "patch": patch}]
        commits = [{"message": "add helper"}]
        result = detect_ai_files(files, commits)
        assert result == []

    def test_large_modified_file_flagged(self):
        """Modified files with 200+ added lines are now detected."""
        patch = "\n".join([f"+line {i}" for i in range(210)])
        files = [{"filename": "existing.py", "status": "modified", "patch": patch}]
        commits = [{"message": "refactor"}]
        result = detect_ai_files(files, commits)
        assert len(result) == 1
        assert result[0][1] == 0.3

    def test_small_modified_file_not_flagged(self):
        patch = "\n".join([f"+line {i}" for i in range(50)])
        files = [{"filename": "existing.py", "status": "modified", "patch": patch}]
        commits = [{"message": "refactor"}]
        result = detect_ai_files(files, commits)
        assert result == []


class TestCombinedHeuristics:
    """Combined scoring across heuristics 2 and 3."""

    def test_new_large_file_with_style_signals(self):
        lines = [f"+line {i}" for i in range(120)]
        lines.insert(5, "+# Step 1: setup")
        lines.insert(10, "+# TODO: Add error handling")
        patch = "\n".join(lines)

        files = [{"filename": "module.py", "status": "added", "patch": patch}]
        commits = [{"message": "add module"}]
        result = detect_ai_files(files, commits)

        assert len(result) == 1
        _, confidence = result[0]
        assert confidence >= 0.7
