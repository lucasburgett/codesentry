import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

_MAX_RETRIES = 3
_RETRY_BACKOFF = 1.0  # seconds, doubled each retry


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _request_with_retry(
    method: str,
    url: str,
    headers: dict,
    json: dict | None = None,
) -> httpx.Response:
    """Make an HTTP request with retry on transient 5xx errors."""
    last_exc = None
    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(method, url, headers=headers, json=json)
                if response.status_code < 500:
                    response.raise_for_status()
                    return response
                logger.warning(
                    "GitHub API %s (attempt %d/%d): %s",
                    response.status_code, attempt + 1, _MAX_RETRIES, url,
                )
                last_exc = httpx.HTTPStatusError(
                    f"{response.status_code}", request=response.request, response=response,
                )
        except httpx.TransportError as exc:
            logger.warning("Transport error (attempt %d/%d): %s", attempt + 1, _MAX_RETRIES, exc)
            last_exc = exc

        if attempt < _MAX_RETRIES - 1:
            await asyncio.sleep(_RETRY_BACKOFF * (2 ** attempt))

    raise last_exc


async def post_comment(token: str, repo_full_name: str, pr_number: int, body: str) -> int:
    """Post a comment on a PR and return the new comment's ID."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments"
    response = await _request_with_retry("POST", url, _headers(token), json={"body": body})
    return response.json()["id"]


async def edit_comment(token: str, repo_full_name: str, comment_id: int, body: str) -> None:
    """Edit an existing issue/PR comment in place."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/issues/comments/{comment_id}"
    await _request_with_retry("PATCH", url, _headers(token), json={"body": body})
