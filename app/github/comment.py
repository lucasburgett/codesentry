import httpx

GITHUB_API = "https://api.github.com"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def post_comment(token: str, repo_full_name: str, pr_number: int, body: str) -> int:
    """Post a comment on a PR and return the new comment's ID."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments"
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=_headers(token), json={"body": body})
        response.raise_for_status()
        return response.json()["id"]


async def edit_comment(token: str, repo_full_name: str, comment_id: int, body: str) -> None:
    """Edit an existing issue/PR comment in place."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/issues/comments/{comment_id}"
    async with httpx.AsyncClient() as client:
        response = await client.patch(url, headers=_headers(token), json={"body": body})
        response.raise_for_status()
