import hashlib
import hmac
import logging
import os
import shutil
import traceback
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request

from app.analysis.detect import detect_ai_files
from app.analysis.diff import get_pr_commits, get_pr_files
from app.analysis.pipeline import write_diff_to_tmp
from app.analysis.semgrep import run_semgrep
from app.db.database import (
    create_analysis,
    create_finding,
    init_db,
    update_analysis_status,
)
from app.github.auth import get_installation_token
from app.github.comment import edit_comment, post_comment

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")


def _validate_config() -> None:
    """Fail fast if required config is missing."""
    missing = []
    if not os.environ.get("GITHUB_APP_ID"):
        missing.append("GITHUB_APP_ID")
    key_path = os.environ.get("GITHUB_PRIVATE_KEY_PATH", "./private-key.pem")
    if not os.path.isfile(key_path):
        missing.append(f"GITHUB_PRIVATE_KEY_PATH (file not found: {key_path})")
    if missing:
        logger.warning("Missing config: %s — webhooks will fail", ", ".join(missing))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _validate_config()
    init_db()
    yield


app = FastAPI(title="CodeSentry", lifespan=lifespan)


def verify_signature(payload: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET not set; skipping signature verification")
        return True
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: str = Header(...),
    x_hub_signature_256: str = Header(...),
):
    payload = await request.body()

    if not verify_signature(payload, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    body = await request.json()

    if x_github_event == "pull_request":
        action = body.get("action")
        if action in ("opened", "synchronize"):
            try:
                pr = body["pull_request"]
                repo = body["repository"]
                installation_id = body["installation"]["id"]
            except (KeyError, TypeError) as exc:
                logger.error("Malformed PR webhook payload: %s", exc)
                return {"ok": False, "error": "malformed payload"}

            logger.info("PR #%s %s on %s", pr["number"], action, repo["full_name"])
            await handle_pr_event(
                installation_id=installation_id,
                repo_full_name=repo["full_name"],
                pr_number=pr["number"],
                pr=pr,
            )

    return {"ok": True}


async def handle_pr_event(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    pr: dict,
):
    token = await get_installation_token(installation_id)
    comment_id = None

    try:
        comment_id = await post_comment(
            token,
            repo_full_name,
            pr_number,
            "🔍 CodeSentry is analyzing this PR...",
        )
        logger.info("Posted comment %s on %s#%s", comment_id, repo_full_name, pr_number)

        files = await get_pr_files(token, repo_full_name, pr_number)
        commits = await get_pr_commits(token, repo_full_name, pr_number)
        ai_files = detect_ai_files(files, commits)

        if not ai_files:
            await edit_comment(
                token, repo_full_name, comment_id,
                "✅ No AI-authored files detected in this PR.",
            )
            logger.info("No AI files detected in %s#%s", repo_full_name, pr_number)
            return

        ai_filenames = {name for name, _ in ai_files}
        filenames_str = ", ".join(sorted(ai_filenames))
        await edit_comment(
            token, repo_full_name, comment_id,
            f"🔍 Detected {len(ai_files)} likely AI-authored file(s): {filenames_str}. "
            "Static analysis running...",
        )

        ai_file_dicts = [f for f in files if f["filename"] in ai_filenames]
        tmp_dir, written_paths = await write_diff_to_tmp(ai_file_dicts, token)

        try:
            semgrep_result = await run_semgrep(written_paths, tmp_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        status = "complete" if semgrep_result.success else "error"
        findings = semgrep_result.findings

        analysis_id = create_analysis(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            pr_head_sha=pr["head"]["sha"],
            comment_id=comment_id,
            status=status,
        )

        for f in findings:
            create_finding(
                analysis_id=analysis_id,
                rule_id=f["rule_id"],
                category=f["category"],
                severity=f["severity"],
                file_path=f["file_path"],
                line_start=f["line_start"],
                message=f["message"],
            )

        body = _format_comment(ai_files, findings, semgrep_result.error)
        await edit_comment(token, repo_full_name, comment_id, body)
        logger.info("Final comment on %s#%s: %s", repo_full_name, pr_number, body[:100])

    except Exception:
        logger.error(
            "Error analyzing %s#%s:\n%s",
            repo_full_name, pr_number, traceback.format_exc(),
        )
        if comment_id:
            try:
                await edit_comment(
                    token, repo_full_name, comment_id,
                    "⚠️ CodeSentry encountered an error analyzing this PR. "
                    "The team has been notified.",
                )
            except Exception:
                logger.error("Failed to update comment with error status")


def _format_comment(
    ai_files: list[tuple[str, float]],
    findings: list[dict],
    semgrep_error: str = "",
) -> str:
    """Build the final PR comment body."""
    ai_filenames = sorted({name for name, _ in ai_files})
    lines = [
        f"🔍 Detected {len(ai_filenames)} likely AI-authored file(s): "
        + ", ".join(ai_filenames),
    ]

    if semgrep_error:
        lines.append(f"\n⚠️ Static analysis error: {semgrep_error}")
        return "\n".join(lines)

    if not findings:
        lines.append("\n✅ No issues found in AI-authored files.")
        return "\n".join(lines)

    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    infos = sum(1 for f in findings if f["severity"] == "info")

    parts = []
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    if warnings:
        parts.append(f"{warnings} warning{'s' if warnings != 1 else ''}")
    if infos:
        parts.append(f"{infos} info")

    lines.append(f"\nFound {len(findings)} issue{'s' if len(findings) != 1 else ''}: {', '.join(parts)}")

    for f in findings:
        lines.append(
            f"  • [{f['category']}] {f['rule_id']} · "
            f"{f['file_path']}:{f['line_start']} — {f['message']}"
        )

    return "\n".join(lines)
