# CodeSentry

AI-powered QA suite that catches bugs in AI-generated code, delivered as a GitHub App.

## Stack
- Python 3.12, FastAPI, Semgrep, Claude API (Haiku)
- SQLite for storage, Fly.io for hosting

## Current phase
Week 1 — GitHub App webhook handler. Goal: receive PR webhook, post placeholder comment.

## Key files
- app/main.py — FastAPI app and webhook handler
- app/github/auth.py — GitHub App JWT auth
- rules/ — Semgrep custom rulesets