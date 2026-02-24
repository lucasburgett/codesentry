#!/usr/bin/env bash
set -euo pipefail

# Push realistic test scenarios to codesentry-test for live E2E webhook testing.
# Usage: bash tests/push_test_scenarios.sh
#
# Prerequisites:
#   - gh CLI authenticated
#   - codesentry-test repo at ../codesentry-test (relative to this repo root)
#   - CodeSentry server running (uvicorn + ngrok or Fly.io)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES="$SCRIPT_DIR/fixtures"
TEST_REPO="${CODESENTRY_TEST_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)/codesentry-test}"

if [ ! -d "$TEST_REPO/.git" ]; then
    echo "ERROR: Test repo not found at $TEST_REPO"
    echo "Set CODESENTRY_TEST_REPO or ensure ../codesentry-test exists"
    exit 1
fi

cd "$TEST_REPO"
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "master")

push_scenario() {
    local branch="$1"
    local commit_msg="$2"
    local fixture_dir="$3"
    local pr_title="$4"

    echo ""
    echo "=== Scenario: $branch ==="

    git checkout "$DEFAULT_BRANCH" 2>/dev/null || git checkout master
    git pull --ff-only origin "$DEFAULT_BRANCH" 2>/dev/null || true

    git checkout -B "$branch"

    # Clean any previous test files
    rm -rf src/ app/ frontend/ backend/ *.py *.ts *.tsx 2>/dev/null || true

    # Copy fixture files
    cp -r "$FIXTURES/$fixture_dir"/* . 2>/dev/null || true

    git add -A
    git commit -m "$commit_msg" --allow-empty

    git push -u origin "$branch" --force

    # Create PR (ignore error if PR already exists)
    gh pr create \
        --title "$pr_title" \
        --body "Automated stress test scenario: $branch" \
        --base "$DEFAULT_BRANCH" \
        --head "$branch" 2>/dev/null || echo "  (PR may already exist)"

    echo "  Done: $branch pushed and PR created"
}

echo "Test repo: $TEST_REPO"
echo "Default branch: $DEFAULT_BRANCH"
echo ""

# Scenario 1: Vibe-coded Flask app
push_scenario \
    "test/vibe-flask-app" \
    "feat: generated with cursor - flask backend" \
    "vibe_flask_app" \
    "[Stress Test] Vibe-coded Flask Backend"

# Scenario 2: Vibe-coded React app
push_scenario \
    "test/vibe-react-app" \
    "generated using copilot - react frontend" \
    "vibe_react_app" \
    "[Stress Test] Vibe-coded React Frontend"

# Scenario 3: Mixed fullstack (both)
echo ""
echo "=== Scenario: test/mixed-fullstack ==="
git checkout "$DEFAULT_BRANCH" 2>/dev/null || git checkout master
git pull --ff-only origin "$DEFAULT_BRANCH" 2>/dev/null || true
git checkout -B "test/mixed-fullstack"
rm -rf src/ app/ frontend/ backend/ *.py *.ts *.tsx 2>/dev/null || true
mkdir -p backend frontend
cp "$FIXTURES/vibe_flask_app"/*.py backend/ 2>/dev/null || true
cp "$FIXTURES/vibe_react_app"/*.ts "$FIXTURES/vibe_react_app"/*.tsx frontend/ 2>/dev/null || true
git add -A
git commit -m "vibe coding session: full-stack app" --allow-empty
git push -u origin "test/mixed-fullstack" --force
gh pr create \
    --title "[Stress Test] Mixed Full-Stack PR" \
    --body "Automated stress test: Python backend + TypeScript frontend" \
    --base "$DEFAULT_BRANCH" \
    --head "test/mixed-fullstack" 2>/dev/null || echo "  (PR may already exist)"
echo "  Done: test/mixed-fullstack pushed"

# Scenario 4: Clean code (should find nothing)
push_scenario \
    "test/clean-code" \
    "fix: improve error handling and types" \
    "clean_app" \
    "[Stress Test] Clean Code - No Issues Expected"

echo ""
echo "=== All scenarios pushed ==="
echo "Check your CodeSentry server logs and GitHub PR comments for results."
