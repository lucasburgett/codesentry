"""Fetch PR files and commits from the GitHub API."""

import httpx

GITHUB_API = "https://api.github.com"

_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def get_pr_files(
    token: str, repo_full_name: str, pr_number: int
) -> list[dict]:
    """
    Fetch PR files from the GitHub API.
    Returns list of dicts with: filename, status, patch, raw_url.
    Filters to .py, .ts, .tsx, .js, .jsx. Caps at 50 files (largest by line count).
    """
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}/files"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=_headers(token))
        response.raise_for_status()
        files = response.json()

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

    if len(filtered) <= 50:
        # Drop internal field before returning
        return [
            {k: v for k, v in f.items() if k != "_changes"}
            for f in filtered
        ]

    sorted_files = sorted(filtered, key=lambda x: x["_changes"], reverse=True)
    top_50 = sorted_files[:50]
    return [{k: v for k, v in f.items() if k != "_changes"} for f in top_50]


async def get_pr_commits(
    token: str, repo_full_name: str, pr_number: int
) -> list[dict]:
    """Fetch PR commits and return list of dicts with commit info (including message)."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}/commits"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=_headers(token))
        response.raise_for_status()
        commits = response.json()

    return [
        {
            "sha": c.get("sha"),
            "message": (c.get("commit") or {}).get("message", ""),
        }
        for c in commits
    ]
