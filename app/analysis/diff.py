"""Fetch PR files and commits from the GitHub API."""

import logging
import re

import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})

_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _paginate(client: httpx.AsyncClient, url: str, headers: dict) -> list:
    """Follow GitHub pagination and collect all items."""
    items: list = []
    while url:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        items.extend(response.json())
        link = response.headers.get("link", "")
        m = _LINK_NEXT_RE.search(link)
        url = m.group(1) if m else None
    return items


async def get_pr_files(
    token: str, repo_full_name: str, pr_number: int
) -> list[dict]:
    """
    Fetch PR files from the GitHub API.
    Returns list of dicts with: filename, status, patch, raw_url.
    Filters to .py, .ts, .tsx, .js, .jsx. Caps at 50 files (largest by change count).
    """
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}/files?per_page=100"
    async with httpx.AsyncClient() as client:
        files = await _paginate(client, url, _headers(token))

    filtered = []
    for f in files:
        name = f.get("filename", "")
        if not any(name.lower().endswith(ext) for ext in _EXTENSIONS):
            continue
        filtered.append(
            {
                "filename": name,
                "status": f.get("status", ""),
                "patch": f.get("patch") or "",
                "raw_url": f.get("raw_url", ""),
                "_changes": f.get("changes", 0),
            }
        )

    if len(filtered) > 50:
        filtered = sorted(filtered, key=lambda x: x["_changes"], reverse=True)[:50]
        logger.info("Capped to 50 files (from %d)", len(filtered))

    return [{k: v for k, v in f.items() if k != "_changes"} for f in filtered]


async def get_pr_commits(
    token: str, repo_full_name: str, pr_number: int
) -> list[dict]:
    """Fetch all PR commits (paginated) and return list of dicts with sha and message."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}/commits?per_page=100"
    async with httpx.AsyncClient() as client:
        commits = await _paginate(client, url, _headers(token))

    return [
        {
            "sha": c.get("sha"),
            "message": (c.get("commit") or {}).get("message", ""),
        }
        for c in commits
    ]
