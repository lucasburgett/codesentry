"""Run Semgrep as a subprocess and parse JSON output."""

import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
_TIMEOUT = 120


async def run_semgrep(
    file_paths: list[str], tmp_dir: str
) -> list[dict]:
    """
    Run Semgrep against *file_paths* using the custom rules in ``rules/``.
    Returns a list of finding dicts with:
    rule_id, category, severity, file_path, line_start, message.
    """
    if not file_paths:
        return []

    rules_dir = os.path.abspath(_RULES_DIR)
    cmd = [
        "semgrep",
        "--config", rules_dir,
        "--json",
        "--no-git-ignore",
        "--quiet",
        *file_paths,
    ]

    logger.info("Running semgrep: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=tmp_dir,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_TIMEOUT)
    except asyncio.TimeoutError:
        logger.error("Semgrep timed out after %ds", _TIMEOUT)
        proc.kill()
        return []
    except FileNotFoundError:
        logger.error("semgrep binary not found — is it installed?")
        return []

    if stderr:
        logger.debug("Semgrep stderr: %s", stderr.decode(errors="replace")[:500])

    if not stdout or not stdout.strip():
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.error("Failed to parse Semgrep JSON output")
        return []

    _SEVERITY_MAP = {
        "ERROR": "error",
        "WARNING": "warning",
        "INFO": "info",
    }

    findings: list[dict] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity_raw = extra.get("severity", "WARNING")
        metadata = extra.get("metadata", {})

        rel_path = result.get("path", "")
        if tmp_dir and rel_path.startswith(tmp_dir):
            rel_path = os.path.relpath(rel_path, tmp_dir)

        findings.append({
            "rule_id": result.get("check_id", "").rsplit(".", 1)[-1],
            "category": metadata.get("category", "unknown"),
            "severity": _SEVERITY_MAP.get(severity_raw, severity_raw.lower()),
            "file_path": rel_path,
            "line_start": result.get("start", {}).get("line", 0),
            "message": extra.get("message", ""),
        })

    logger.info("Semgrep found %d findings", len(findings))
    return findings
