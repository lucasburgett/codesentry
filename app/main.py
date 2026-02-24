import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import traceback
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analysis.detect import detect_ai_files
from app.analysis.diff import get_pr_commits, get_pr_files
from app.analysis.llm import (
    build_prompt,
    call_claude,
    deduplicate_flags,
    filter_flags_by_evidence,
    parse_llm_response,
)
from app.analysis.pipeline import write_diff_to_tmp
from app.analysis.semgrep import run_semgrep
from app.db.database import (
    cache_llm_result,
    check_rate_limit,
    create_analysis,
    create_finding,
    dismiss_finding,
    get_cached_llm_result,
    get_comment_id_for_pr,
    get_cost_stats,
    get_dismissed_rules_for_pr,
    get_latest_analysis_for_pr,
    init_db,
    save_llm_cost,
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
    if not os.environ.get("ANTHROPIC_API_KEY"):
        missing.append("ANTHROPIC_API_KEY")
    if missing:
        logger.warning("Missing config: %s — some features will be unavailable", ", ".join(missing))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _validate_config()
    init_db()
    yield


app = FastAPI(title="CodeSentry", lifespan=lifespan)


@app.get("/")
async def landing():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")


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


@app.get("/stats")
async def stats():
    return get_cost_stats()


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

    elif x_github_event == "issue_comment":
        if body.get("action") == "created":
            await handle_dismiss_comment(body)

    return {"ok": True}


_DISMISS_PATTERN = re.compile(
    r"codesentry[:\s]+ignore\s+([^\s:]+)[:\s]+(.+)",
    re.IGNORECASE,
)


async def handle_dismiss_comment(body: dict) -> None:
    """Handle an issue_comment event looking for dismiss commands."""
    try:
        issue = body["issue"]
        comment = body["comment"]
        repo_full_name = body["repository"]["full_name"]
        installation_id = body["installation"]["id"]
    except (KeyError, TypeError):
        return

    if "pull_request" not in issue:
        return

    if comment.get("user", {}).get("type") == "Bot":
        return

    comment_body = comment.get("body", "")
    match = _DISMISS_PATTERN.search(comment_body)
    if not match:
        return

    rule_id = match.group(1)
    reason = match.group(2).strip()
    pr_number = issue["number"]

    token = await get_installation_token(installation_id)
    analysis = get_latest_analysis_for_pr(repo_full_name, pr_number)

    if not analysis:
        await post_comment(
            token, repo_full_name, pr_number,
            f"⚠️ No active finding for rule `{rule_id}` on this PR.",
        )
        return

    dismissed = dismiss_finding(analysis["id"], rule_id, reason)
    if dismissed:
        await post_comment(
            token, repo_full_name, pr_number,
            f"✅ Dismissed `{rule_id}`. It will be suppressed in future analyses of this PR.",
        )
    else:
        await post_comment(
            token, repo_full_name, pr_number,
            f"⚠️ No active finding for rule `{rule_id}` on this PR.",
        )


async def handle_pr_event(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    pr: dict,
):
    token = await get_installation_token(installation_id)
    head_sha = pr["head"]["sha"]
    comment_id = None

    try:
        # Step a: reuse existing comment on re-push, or post a new one
        existing_comment_id = get_comment_id_for_pr(repo_full_name, pr_number)
        if existing_comment_id:
            comment_id = existing_comment_id
            try:
                await edit_comment(
                    token, repo_full_name, comment_id,
                    "🔍 CodeSentry is analyzing this PR...",
                )
            except Exception:
                logger.warning("Failed to edit comment %s (may be deleted), posting new one", comment_id)
                comment_id = await post_comment(
                    token, repo_full_name, pr_number,
                    "🔍 CodeSentry is analyzing this PR...",
                )
        else:
            comment_id = await post_comment(
                token, repo_full_name, pr_number,
                "🔍 CodeSentry is analyzing this PR...",
            )
        logger.info("Using comment %s on %s#%s", comment_id, repo_full_name, pr_number)

        if not check_rate_limit(installation_id):
            await edit_comment(
                token, repo_full_name, comment_id,
                "⏸️ Rate limit reached (20 analyses/hour). Analysis will resume shortly.",
            )
            return

        # Step b: fetch diff + commits
        files = await get_pr_files(token, repo_full_name, pr_number)
        commits = await get_pr_commits(token, repo_full_name, pr_number)

        # Step c: AI detection
        ai_files = detect_ai_files(files, commits)

        ai_filenames = {name for name, _ in ai_files}
        if ai_files:
            filenames_str = ", ".join(sorted(ai_filenames))
            await edit_comment(
                token, repo_full_name, comment_id,
                f"🔍 Detected {len(ai_files)} likely AI-authored file(s): {filenames_str}. "
                "Static analysis running...",
            )
        else:
            await edit_comment(
                token, repo_full_name, comment_id,
                "🔍 No AI-authored files detected. Running static analysis on all files...",
            )

        # Step d: run Semgrep on ALL files (not just AI-authored)
        tmp_dir, written_paths = await write_diff_to_tmp(files, token)

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
            pr_head_sha=head_sha,
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

        dismissed_rules = get_dismissed_rules_for_pr(repo_full_name, pr_number)
        if dismissed_rules:
            findings = [f for f in findings if f["rule_id"] not in dismissed_rules]

        interim_body = _format_comment(
            ai_files, findings, head_sha=head_sha,
            semgrep_error=semgrep_result.error,
            is_final=False,
        )
        await edit_comment(token, repo_full_name, comment_id, interim_body)

        # Steps e-f: LLM behavioral summary (with cache)
        llm_summary = None
        behavioral_flags: list[dict] = []

        cached = get_cached_llm_result(head_sha)
        if cached:
            logger.info("LLM cache hit for %s", head_sha[:7])
            llm_summary = cached["summary"]
            behavioral_flags = cached.get("flags", [])
        else:
            try:
                prompt = build_prompt(files)
                if prompt is not None:
                    raw_response = await call_claude(prompt)
                    if "error" not in raw_response:
                        parsed = parse_llm_response(raw_response["text"])
                        llm_summary = parsed.get("summary", "")
                        behavioral_flags = parsed.get("behavioral_flags", [])
                        cache_llm_result(
                            head_sha, llm_summary,
                            json.dumps(behavioral_flags),
                        )
                        if "input_tokens" in raw_response:
                            save_llm_cost(
                                analysis_id,
                                raw_response["input_tokens"],
                                raw_response["output_tokens"],
                                raw_response["cost_usd"],
                            )
                    else:
                        logger.warning("Claude unavailable: %s", raw_response["error"])
            except ValueError as exc:
                logger.warning("LLM skipped: %s", exc)

        # Step g: deduplicate, then filter by evidence level
        if behavioral_flags and findings:
            behavioral_flags = deduplicate_flags(behavioral_flags, findings)
        behavioral_flags = filter_flags_by_evidence(behavioral_flags, findings)

        # Step h: final comment with full format
        final_body = _format_comment(
            ai_files, findings, head_sha=head_sha,
            llm_summary=llm_summary,
            behavioral_flags=behavioral_flags if behavioral_flags else None,
            semgrep_error=semgrep_result.error,
        )
        await edit_comment(token, repo_full_name, comment_id, final_body)
        logger.info("Final comment on %s#%s: %s", repo_full_name, pr_number, final_body[:120])

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
    head_sha: str = "",
    llm_summary: str | None = None,
    behavioral_flags: list[dict] | None = None,
    semgrep_error: str = "",
    is_final: bool = True,
) -> str:
    """Build the rich PR comment body."""
    ai_filenames = sorted({name for name, _ in ai_files})

    risk = _compute_risk(findings, behavioral_flags)
    risk_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}[risk]

    lines: list[str] = []
    lines.append("## 🔍 CodeSentry Analysis")
    lines.append("")
    total_issues = len(findings) + (len(behavioral_flags) if behavioral_flags else 0)
    lines.append(
        f"**Risk:** {risk_emoji} {risk} | "
        f"**AI-authored files:** {len(ai_filenames)} | "
        f"**Issues:** {total_issues}"
    )
    if ai_filenames:
        lines.append("")
        lines.append("**Files:** " + ", ".join(f"`{n}`" for n in ai_filenames))

    # LLM summary section
    lines.append("")
    if llm_summary:
        lines.append("### What this code does")
        lines.append(llm_summary)
    elif is_final:
        lines.append("⚠️ Behavioral summary unavailable.")
    else:
        lines.append("⏳ Behavioral analysis running...")

    if semgrep_error:
        lines.append("")
        lines.append(f"⚠️ Static analysis error: {semgrep_error}")

    # Static analysis findings — grouped by file
    from collections import defaultdict
    if findings:
        lines.append("")
        lines.append(f"### Static Analysis ({len(findings)} finding{'s' if len(findings) != 1 else ''})")

        errors = sum(1 for f in findings if f["severity"] == "error")
        warnings = sum(1 for f in findings if f["severity"] == "warning")
        infos = sum(1 for f in findings if f["severity"] == "info")
        summary_parts = []
        if errors:
            summary_parts.append(f"🔴 {errors} error{'s' if errors != 1 else ''}")
        if warnings:
            summary_parts.append(f"🟡 {warnings} warning{'s' if warnings != 1 else ''}")
        if infos:
            summary_parts.append(f"ℹ️ {infos} info")
        if summary_parts:
            lines.append(" · ".join(summary_parts))

        by_file: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            by_file[f["file_path"]].append(f)

        for filepath in sorted(by_file):
            file_findings = by_file[filepath]
            file_errors = sum(1 for f in file_findings if f["severity"] == "error")
            file_warnings = sum(1 for f in file_findings if f["severity"] == "warning")
            file_infos = sum(1 for f in file_findings if f["severity"] == "info")
            badge_parts = []
            if file_errors:
                badge_parts.append(f"{file_errors}E")
            if file_warnings:
                badge_parts.append(f"{file_warnings}W")
            if file_infos:
                badge_parts.append(f"{file_infos}I")
            badge = ", ".join(badge_parts)

            lines.append("")
            lines.append("<details>")
            lines.append(f"<summary><strong>{filepath}</strong> — {len(file_findings)} issue{'s' if len(file_findings) != 1 else ''} ({badge})</summary>")
            lines.append("")
            for f in sorted(file_findings, key=lambda x: x["line_start"]):
                sev_icon = {"error": "🔴", "warning": "🟡", "info": "ℹ️"}.get(f["severity"], "·")
                lines.append(
                    f"- {sev_icon} **L{f['line_start']}** `{f['rule_id']}` — {f['message']}"
                )
            lines.append("")
            lines.append("</details>")

    elif not semgrep_error:
        lines.append("")
        if behavioral_flags:
            lines.append("✅ No static analysis issues found.")
        else:
            lines.append("✅ No issues found.")

    # Behavioral flags — grouped by file, same format as static analysis
    if behavioral_flags:
        lines.append("")
        lines.append(f"### Behavioral Analysis ({len(behavioral_flags)} flag{'s' if len(behavioral_flags) != 1 else ''})")

        sev_icon_map = {"high": "🔴", "medium": "🟡", "low": "ℹ️"}
        high_count = sum(1 for f in behavioral_flags if f.get("severity") == "high")
        med_count = sum(1 for f in behavioral_flags if f.get("severity") == "medium")
        low_count = sum(1 for f in behavioral_flags if f.get("severity") == "low")
        sev_parts = []
        if high_count:
            sev_parts.append(f"🔴 {high_count} high")
        if med_count:
            sev_parts.append(f"🟡 {med_count} medium")
        if low_count:
            sev_parts.append(f"ℹ️ {low_count} low")
        if sev_parts:
            lines.append(" · ".join(sev_parts))

        by_file_b: dict[str, list[dict]] = defaultdict(list)
        ungrouped: list[dict] = []
        for flag in behavioral_flags:
            loc = flag.get("location", "")
            parts = loc.split(":", 1) if loc else []
            if len(parts) >= 1 and parts[0]:
                by_file_b[parts[0]].append(flag)
            else:
                ungrouped.append(flag)

        for filepath in sorted(by_file_b):
            file_flags = by_file_b[filepath]
            fh = sum(1 for f in file_flags if f.get("severity") == "high")
            fm = sum(1 for f in file_flags if f.get("severity") == "medium")
            fl = sum(1 for f in file_flags if f.get("severity") == "low")
            bp = []
            if fh:
                bp.append(f"{fh}H")
            if fm:
                bp.append(f"{fm}M")
            if fl:
                bp.append(f"{fl}L")
            badge = ", ".join(bp)

            lines.append("")
            lines.append("<details>")
            lines.append(f"<summary><strong>{filepath}</strong> — {len(file_flags)} flag{'s' if len(file_flags) != 1 else ''} ({badge})</summary>")
            lines.append("")
            for flag in file_flags:
                sev = flag.get("severity", "medium")
                icon = sev_icon_map.get(sev, "🟡")
                loc = flag.get("location", "")
                line_part = loc.split(":", 1)[1] if ":" in loc else ""
                desc = flag.get("flag", "")
                if line_part:
                    lines.append(f"- {icon} **L{line_part}** — {desc}")
                else:
                    lines.append(f"- {icon} — {desc}")
            lines.append("")
            lines.append("</details>")

        if ungrouped:
            lines.append("")
            lines.append("<details>")
            lines.append(f"<summary><strong>General</strong> — {len(ungrouped)} flag{'s' if len(ungrouped) != 1 else ''}</summary>")
            lines.append("")
            for flag in ungrouped:
                sev = flag.get("severity", "medium")
                icon = sev_icon_map.get(sev, "🟡")
                desc = flag.get("flag", "")
                lines.append(f"- {icon} — {desc}")
            lines.append("")
            lines.append("</details>")

    # Footer
    lines.append("")
    lines.append("---")
    sha_display = head_sha[:7] if head_sha else "unknown"
    lines.append(f"_Analyzed commit `{sha_display}`_")
    lines.append("")
    lines.append("_To dismiss a finding, reply_ `codesentry ignore rule-id: reason`")

    return "\n".join(lines)


def _compute_risk(
    findings: list[dict],
    behavioral_flags: list[dict] | None,
) -> str:
    """Determine overall risk level from findings and behavioral flags.

    High requires a confirmed Semgrep ERROR finding.  Behavioral flags
    alone cannot produce a risk above Low unless at least one flag is
    high severity AND there is at least one Semgrep finding.
    """
    if any(f.get("severity") == "error" for f in findings):
        return "High"
    if any(f.get("severity") == "warning" for f in findings):
        return "Medium"
    if behavioral_flags and findings and any(
        f.get("severity") == "high" for f in behavioral_flags
    ):
        return "Medium"
    return "Low"
