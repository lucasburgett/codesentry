# CodeSentry

AI-powered code review for AI-generated code, delivered as a GitHub App.

CodeSentry automatically analyzes pull requests to catch bugs, security issues, and anti-patterns in AI-generated code. It combines static analysis (Semgrep) with behavioral analysis (Claude) to surface problems that each tool would miss alone.

## How it works

When a PR is opened or updated, CodeSentry:

1. **Detects AI-authored files** using three heuristics: commit message patterns (e.g. "generated with Cursor"), code style signals (step comments, uniform formatting), and large-change signals
2. **Runs Semgrep** with 16 custom rules targeting common AI code mistakes — hardcoded secrets, bare excepts, SQL injection via f-strings, missing error handling, `dangerouslySetInnerHTML`, and more
3. **Calls Claude Haiku** to generate a behavioral summary and flag edge cases a static linter can't catch — race conditions, missing validation, silent failures
4. **Posts a PR comment** with a risk score, grouped findings, and an LLM behavioral summary

```
## CodeSentry Analysis

**Risk:** Medium | **AI-authored files:** 2 | **Issues:** 3

### What this code does
This PR adds a new authentication endpoint that accepts username/password
credentials and returns a JWT token...

### Static Analysis (2 findings)
 1 error · 1 warning

  app.py — 2 issues (1E, 1W)
  - L3  hardcoded-secret-string — Hardcoded secret in variable
  - L18 broad-exception-catch — Catching bare Exception

### Behavioral Analysis (1 flag)
  - Missing rate limiting on login endpoint
```

## Features

- **False positive suppression** — LLM flags are gated by Semgrep evidence. If Semgrep finds nothing, only high-severity LLM flags survive. If fewer than 2 flags pass filtering, the section is suppressed entirely.
- **Dismiss findings** — Reply `codesentry ignore rule-id: reason` on any PR comment to suppress a finding for that PR.
- **Re-push handling** — Subsequent pushes to the same PR edit the existing comment instead of posting duplicates.
- **LLM caching** — Behavioral analysis is cached by commit SHA so re-analyses don't re-call the API.
- **Rate limiting** — 20 analyses per hour per installation to prevent abuse.
- **Cost tracking** — Token usage and estimated cost logged per analysis, queryable via `GET /stats`.

## Stack

- **Python 3.11+**, **FastAPI**, **uvicorn**
- **Semgrep** — 16 custom rules across Python and TypeScript/JSX
- **Claude Haiku** (via Anthropic API) — behavioral summary and risk flagging
- **SQLite** — analyses, findings, LLM cache, rate limits
- **Fly.io** — deployment target (Dockerfile included)

## Project structure

```
app/
  main.py              Webhook handler, comment formatting, risk scoring
  analysis/
    detect.py          AI-authored file detection (3 heuristics)
    diff.py            GitHub PR file + commit fetching
    llm.py             Claude API calls, response parsing, flag filtering
    pipeline.py        Temp file management for Semgrep
    semgrep.py         Semgrep subprocess runner + output parsing
  db/
    database.py        SQLite schema, migrations, all data access
  github/
    auth.py            GitHub App JWT → installation token
    comment.py         Post/edit PR comments with retry
rules/
  python/              9 Semgrep rules for Python
  typescript/          7 Semgrep rules for TypeScript/JSX
static/
  index.html           Landing page
  privacy.html         Privacy policy
tests/                 165+ tests across 11 test files
```

## Setup

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- A [GitHub App](https://docs.github.com/en/apps/creating-github-apps) configured with:
  - Webhook URL pointing to your server (use [ngrok](https://ngrok.com/) for local dev)
  - Permissions: Pull Requests (read/write), Issues (read/write), Contents (read)
  - Events: Pull request, Issue comment
- An [Anthropic API key](https://console.anthropic.com/)

### Install and run

```bash
# Install dependencies
uv sync

# Configure environment
cp .env.example .env
# Edit .env with your GitHub App ID, private key path, webhook secret, and Anthropic API key

# Start the server
uv run uvicorn app.main:app --reload --port 8000

# In another terminal, expose via ngrok
ngrok http 8000
```

Set the ngrok URL as your GitHub App's webhook URL (e.g. `https://abc123.ngrok.io/webhook`).

### Run tests

```bash
uv run pytest tests/ -v
```

## Deployment

See [DEPLOY.md](DEPLOY.md) for Fly.io deployment instructions.

## License

MIT
