import os
import time

import httpx
import jwt

GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_PRIVATE_KEY_PATH = os.environ.get("GITHUB_PRIVATE_KEY_PATH", "./private-key.pem")


def _load_private_key() -> str:
    with open(GITHUB_PRIVATE_KEY_PATH) as f:
        return f.read()


def _generate_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,        # issued 60s ago to cover clock skew
        "exp": now + (10 * 60), # expires in 10 minutes
        "iss": int(GITHUB_APP_ID),
    }
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    """Exchange a GitHub App JWT for an installation access token."""
    app_jwt = _generate_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers)
        response.raise_for_status()
        return response.json()["token"]
