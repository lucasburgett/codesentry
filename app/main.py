import hashlib
import hmac
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request

from app.analysis.detect import detect_ai_files
from app.analysis.diff import get_pr_commits, get_pr_files
from app.db.database import create_analysis, init_db
from app.github.auth import get_installation_token
from app.github.comment import edit_comment, post_comment

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")


@asynccontextmanager
async def lifespan(_app: FastAPI):
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
            pr = body["pull_request"]
            repo = body["repository"]
            installation_id = body["installation"]["id"]
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

    if ai_files:
        filenames = ", ".join(f[0] for f in ai_files)
        body = f"🔍 Detected {len(ai_files)} likely AI-authored files: {filenames}. Static analysis running..."
    else:
        body = "✅ No AI-authored files detected in this PR."

    await edit_comment(token, repo_full_name, comment_id, body)
    logger.info("Updated comment: %s", body[:80])

    analysis_id = create_analysis(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        pr_head_sha=pr["head"]["sha"],
        comment_id=comment_id,
        status="pending",
    )
    logger.info("Saved analysis id=%s for %s#%s", analysis_id, repo_full_name, pr_number)
