"""
Send a fake PR webhook to the locally running CodeSentry server.

Usage:
    uv run python tests/send_test_webhook.py

Requires the server to be running: uv run uvicorn app.main:app --reload --port 8080
"""

import hashlib
import hmac
import json
import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = os.environ.get("TEST_WEBHOOK_URL", "http://localhost:8080/webhook")
WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

PAYLOAD = {
    "action": "opened",
    "pull_request": {
        "number": 1,
        "head": {"sha": "fake123abc"},
    },
    "repository": {"full_name": "lucasburgett/codesentry-test"},
    "installation": {"id": 111193863},
}


def sign(payload_bytes: bytes, secret: str) -> str:
    sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def main():
    body = json.dumps(PAYLOAD).encode()
    signature = sign(body, WEBHOOK_SECRET) if WEBHOOK_SECRET else "sha256=none"

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": signature,
    }

    print(f"Sending webhook to {SERVER_URL}")
    print(f"Payload: PR #{PAYLOAD['pull_request']['number']} "
          f"on {PAYLOAD['repository']['full_name']}")
    print(f"Signature: {signature[:30]}...")
    print()

    try:
        resp = httpx.post(SERVER_URL, content=body, headers=headers, timeout=30)
    except httpx.ConnectError:
        print("ERROR: Could not connect. Is the server running?")
        print("  Start it with: uv run uvicorn app.main:app --reload --port 8080")
        sys.exit(1)

    print(f"Response: {resp.status_code}")
    print(f"Body: {resp.text}")

    if resp.status_code == 200:
        print("\nWebhook accepted! Check the uvicorn terminal for log output.")
    else:
        print(f"\nWebhook rejected with {resp.status_code}. Check server logs.")


if __name__ == "__main__":
    main()
