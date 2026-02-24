"""Stress tests: run real Semgrep against multi-file realistic fixtures."""

import os
import shutil
import tempfile

import pytest

from app.analysis.semgrep import run_semgrep

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _copy_dir(src_name: str, tmp_dir: str) -> list[str]:
    """Copy an entire fixture directory into tmpdir and return all file paths."""
    src = os.path.join(FIXTURES, src_name)
    paths: list[str] = []
    for root, _dirs, files in os.walk(src):
        for fname in files:
            if fname.startswith(".") or fname == "__pycache__":
                continue
            src_path = os.path.join(root, fname)
            rel = os.path.relpath(src_path, FIXTURES)
            dst = os.path.join(tmp_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src_path, dst)
            paths.append(dst)
    return paths


def _copy_file(src_name: str, tmp_dir: str) -> str:
    src = os.path.join(FIXTURES, src_name)
    dst = os.path.join(tmp_dir, os.path.basename(src_name))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="codesentry-stress-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


PYTHON_RULES = {
    "hardcoded-secret-string",
    "sql-fstring-injection",
    "bare-except-swallows-errors",
    "unchecked-requests-response",
    "open-without-context-manager",
    "subprocess-shell-true",
    "eval-or-exec-usage",
    "mutable-default-argument",
    "assert-used-for-validation",
}

TS_RULES = {
    "promise-without-catch",
    "console-log-left-in",
    "hardcoded-url-string",
    "any-type-escape-hatch",
    "non-null-assertion",
    "dangerously-set-inner-html",
    "no-await-in-loop",
}


@pytest.mark.asyncio
async def test_flask_app_catches_all_rules(tmp_dir):
    paths = _copy_dir("vibe_flask_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    assert result.success
    rule_ids = {f["rule_id"] for f in result.findings}
    missing = PYTHON_RULES - rule_ids
    assert not missing, f"Missing Python rules: {missing}"


@pytest.mark.asyncio
async def test_flask_app_finding_count(tmp_dir):
    paths = _copy_dir("vibe_flask_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    assert result.success
    assert len(result.findings) >= 12, (
        f"Expected >= 12 findings, got {len(result.findings)}: "
        f"{[f['rule_id'] for f in result.findings]}"
    )


@pytest.mark.asyncio
async def test_flask_app_severity_distribution(tmp_dir):
    paths = _copy_dir("vibe_flask_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    errors = [f for f in result.findings if f["severity"] == "error"]
    warnings = [f for f in result.findings if f["severity"] == "warning"]
    assert len(errors) >= 4, f"Expected >= 4 errors, got {len(errors)}"
    assert len(warnings) >= 4, f"Expected >= 4 warnings, got {len(warnings)}"


@pytest.mark.asyncio
async def test_react_app_catches_all_rules(tmp_dir):
    paths = _copy_dir("vibe_react_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    assert result.success
    rule_ids = {f["rule_id"] for f in result.findings}
    missing = TS_RULES - rule_ids
    assert not missing, f"Missing TS rules: {missing}"


@pytest.mark.asyncio
async def test_react_app_finding_count(tmp_dir):
    paths = _copy_dir("vibe_react_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    assert result.success
    assert len(result.findings) >= 10, (
        f"Expected >= 10 findings, got {len(result.findings)}: "
        f"{[f['rule_id'] for f in result.findings]}"
    )


@pytest.mark.asyncio
async def test_clean_app_zero_findings(tmp_dir):
    paths = _copy_dir("clean_app", tmp_dir)
    result = await run_semgrep(paths, tmp_dir)

    assert result.success
    assert result.findings == [], (
        f"Expected 0 findings in clean app, got: "
        f"{[(f['rule_id'], f['file_path'], f['line_start']) for f in result.findings]}"
    )


@pytest.mark.asyncio
async def test_mixed_language_pr(tmp_dir):
    flask_paths = _copy_dir("vibe_flask_app", tmp_dir)
    react_paths = _copy_dir("vibe_react_app", tmp_dir)
    all_paths = flask_paths + react_paths

    result = await run_semgrep(all_paths, tmp_dir)
    assert result.success

    rule_ids = {f["rule_id"] for f in result.findings}
    py_found = rule_ids & PYTHON_RULES
    ts_found = rule_ids & TS_RULES
    assert len(py_found) >= 5, f"Expected >= 5 Python rules, found: {py_found}"
    assert len(ts_found) >= 4, f"Expected >= 4 TS rules, found: {ts_found}"


@pytest.mark.asyncio
async def test_large_file_completes_under_timeout(tmp_dir):
    path = _copy_file("edge_cases/huge_file.py", tmp_dir)
    result = await run_semgrep([path], tmp_dir)

    assert result.success
    assert "timed out" not in result.error
