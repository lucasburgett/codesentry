"""Tests for Semgrep rule execution via run_semgrep()."""

import os
import shutil
import tempfile

import pytest
import pytest_asyncio

from app.analysis.semgrep import run_semgrep

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _copy_fixture(name: str, tmp_dir: str) -> str:
    """Copy a fixture into a tmpdir so path-based rule exclusions don't interfere."""
    src = os.path.join(FIXTURES, name)
    dst = os.path.join(tmp_dir, name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="codesentry-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_bad_python_fires_all_rules(tmp_dir):
    path = _copy_fixture("bad_python.py", tmp_dir)
    findings = await run_semgrep([path], tmp_dir)

    rule_ids = {f["rule_id"] for f in findings}
    expected = {
        "hardcoded-secret-string",
        "sql-fstring-injection",
        "bare-except-swallows-errors",
        "unchecked-requests-response",
        "open-without-context-manager",
    }
    assert expected.issubset(rule_ids), f"Missing rules: {expected - rule_ids}"
    assert len(findings) >= 5


@pytest.mark.asyncio
async def test_clean_python_has_no_findings(tmp_dir):
    path = _copy_fixture("clean_python.py", tmp_dir)
    findings = await run_semgrep([path], tmp_dir)
    assert findings == []


@pytest.mark.asyncio
async def test_bad_typescript_fires_all_rules(tmp_dir):
    path = _copy_fixture("bad_typescript.ts", tmp_dir)
    findings = await run_semgrep([path], tmp_dir)

    rule_ids = {f["rule_id"] for f in findings}
    expected = {
        "promise-without-catch",
        "console-log-left-in",
        "hardcoded-url-string",
        "any-type-escape-hatch",
    }
    assert expected.issubset(rule_ids), f"Missing rules: {expected - rule_ids}"


@pytest.mark.asyncio
async def test_empty_file_list_returns_empty():
    findings = await run_semgrep([], "/tmp")
    assert findings == []


@pytest.mark.asyncio
async def test_finding_fields_are_populated(tmp_dir):
    path = _copy_fixture("bad_python.py", tmp_dir)
    findings = await run_semgrep([path], tmp_dir)

    for f in findings:
        assert f["rule_id"], "rule_id should be non-empty"
        assert f["category"] in ("security", "correctness", "quality", "unknown")
        assert f["severity"] in ("error", "warning", "info")
        assert f["file_path"], "file_path should be non-empty"
        assert f["line_start"] > 0, "line_start should be positive"
        assert f["message"], "message should be non-empty"
