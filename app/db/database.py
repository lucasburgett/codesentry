import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_is_production = os.environ.get("IS_PRODUCTION", "").lower() in ("true", "1")
DATABASE_PATH = os.environ.get(
    "DATABASE_PATH",
    "/data/codesentry.db" if _is_production else "./data/codesentry.db",
)

_CREATE_ANALYSES = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER NOT NULL,
    repo_full_name  TEXT    NOT NULL,
    pr_number       INTEGER NOT NULL,
    pr_head_sha     TEXT    NOT NULL,
    comment_id      INTEGER,
    status          TEXT    NOT NULL DEFAULT 'pending',
    llm_summary     TEXT,
    llm_flags       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
)
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    rule_id     TEXT,
    category    TEXT,
    severity    TEXT,
    file_path   TEXT,
    line_start  INTEGER,
    message     TEXT,
    dismissed   INTEGER NOT NULL DEFAULT 0
)
"""


_CREATE_RATE_LIMITS = """
CREATE TABLE IF NOT EXISTS rate_limits (
    installation_id INTEGER PRIMARY KEY,
    window_start    TEXT NOT NULL,
    analysis_count  INTEGER NOT NULL DEFAULT 0
)
"""


def _connect() -> sqlite3.Connection:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_llm_columns(conn: sqlite3.Connection) -> None:
    """Add llm_summary and llm_flags columns if missing (existing DBs)."""
    rows = conn.execute("PRAGMA table_info(analyses)").fetchall()
    existing = {row["name"] for row in rows}
    if "llm_summary" not in existing:
        conn.execute("ALTER TABLE analyses ADD COLUMN llm_summary TEXT")
    if "llm_flags" not in existing:
        conn.execute("ALTER TABLE analyses ADD COLUMN llm_flags TEXT")


def _migrate_dismissed_columns(conn: sqlite3.Connection) -> None:
    """Add dismissed_reason and dismissed_at columns to findings if missing."""
    rows = conn.execute("PRAGMA table_info(findings)").fetchall()
    existing = {row["name"] for row in rows}
    if "dismissed_reason" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN dismissed_reason TEXT")
    if "dismissed_at" not in existing:
        conn.execute("ALTER TABLE findings ADD COLUMN dismissed_at TEXT")


def _migrate_cost_columns(conn: sqlite3.Connection) -> None:
    """Add LLM cost tracking columns to analyses if missing."""
    rows = conn.execute("PRAGMA table_info(analyses)").fetchall()
    existing = {row["name"] for row in rows}
    if "llm_input_tokens" not in existing:
        conn.execute("ALTER TABLE analyses ADD COLUMN llm_input_tokens INTEGER")
    if "llm_output_tokens" not in existing:
        conn.execute("ALTER TABLE analyses ADD COLUMN llm_output_tokens INTEGER")
    if "llm_cost_usd" not in existing:
        conn.execute("ALTER TABLE analyses ADD COLUMN llm_cost_usd REAL")


def init_db() -> None:
    """Create tables if they don't exist. Called once at app startup."""
    with _connect() as conn:
        conn.execute(_CREATE_ANALYSES)
        conn.execute(_CREATE_FINDINGS)
        conn.execute(_CREATE_RATE_LIMITS)
        _migrate_llm_columns(conn)
        _migrate_dismissed_columns(conn)
        _migrate_cost_columns(conn)


def create_finding(
    analysis_id: int,
    rule_id: str,
    category: str,
    severity: str,
    file_path: str,
    line_start: int,
    message: str,
) -> int:
    """Insert a finding row and return its id."""
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO findings
                (analysis_id, rule_id, category, severity, file_path, line_start, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (analysis_id, rule_id, category, severity, file_path, line_start, message),
        )
        return cursor.lastrowid


def update_analysis_status(analysis_id: int, status: str) -> None:
    """Update the status of an analysis."""
    with _connect() as conn:
        conn.execute(
            "UPDATE analyses SET status = ? WHERE id = ?",
            (status, analysis_id),
        )


def create_analysis(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    pr_head_sha: str,
    comment_id: int | None,
    status: str = "pending",
) -> int:
    """Insert a new analysis row and return its id."""
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses
                (installation_id, repo_full_name, pr_number, pr_head_sha, comment_id, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (installation_id, repo_full_name, pr_number, pr_head_sha, comment_id, status),
        )
        return cursor.lastrowid


def cache_llm_result(head_sha: str, summary: str, flags: str) -> None:
    """Save LLM result to the most recent analysis row for this SHA."""
    with _connect() as conn:
        conn.execute(
            """
            UPDATE analyses
            SET llm_summary = ?, llm_flags = ?
            WHERE id = (
                SELECT id FROM analyses
                WHERE pr_head_sha = ?
                ORDER BY id DESC LIMIT 1
            )
            """,
            (summary, flags, head_sha),
        )


def get_cached_llm_result(head_sha: str) -> dict | None:
    """Return cached LLM result for this SHA, or None if not cached."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT llm_summary, llm_flags FROM analyses
            WHERE pr_head_sha = ? AND llm_summary IS NOT NULL
            ORDER BY id DESC LIMIT 1
            """,
            (head_sha,),
        ).fetchone()
    if row is None:
        return None
    flags_raw = row["llm_flags"] or "[]"
    try:
        flags = json.loads(flags_raw)
    except (json.JSONDecodeError, TypeError):
        flags = []
    return {"summary": row["llm_summary"], "flags": flags}


# --- Dismiss mechanism ---

def get_active_findings(analysis_id: int) -> list[dict]:
    """Return non-dismissed findings for an analysis."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE analysis_id = ? AND dismissed = 0",
            (analysis_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def dismiss_finding(analysis_id: int, rule_id: str, reason: str) -> bool:
    """Mark findings with the given rule_id as dismissed. Returns True if any rows updated."""
    with _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE findings
            SET dismissed = 1, dismissed_reason = ?, dismissed_at = ?
            WHERE analysis_id = ? AND rule_id = ? AND dismissed = 0
            """,
            (reason, datetime.now(timezone.utc).isoformat(), analysis_id, rule_id),
        )
        return cursor.rowcount > 0


def get_latest_analysis_for_pr(repo_full_name: str, pr_number: int) -> dict | None:
    """Return the most recent analysis row for a repo + PR, or None."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM analyses
            WHERE repo_full_name = ? AND pr_number = ?
            ORDER BY id DESC LIMIT 1
            """,
            (repo_full_name, pr_number),
        ).fetchone()
    return dict(row) if row else None


def get_dismissed_rules_for_pr(repo_full_name: str, pr_number: int) -> set[str]:
    """Return all rule_ids dismissed across any analysis for this PR."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT f.rule_id
            FROM findings f
            JOIN analyses a ON f.analysis_id = a.id
            WHERE a.repo_full_name = ? AND a.pr_number = ? AND f.dismissed = 1
            """,
            (repo_full_name, pr_number),
        ).fetchall()
    return {row["rule_id"] for row in rows}


def get_comment_id_for_pr(repo_full_name: str, pr_number: int) -> int | None:
    """Return the most recent comment_id for a repo + PR, or None."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT comment_id FROM analyses
            WHERE repo_full_name = ? AND pr_number = ? AND comment_id IS NOT NULL
            ORDER BY id DESC LIMIT 1
            """,
            (repo_full_name, pr_number),
        ).fetchone()
    return row["comment_id"] if row else None


# --- Rate limiting ---

def check_rate_limit(installation_id: int) -> bool:
    """Return True (allowed) if under 20 analyses/hour, False if blocked.

    Uses a fixed-window approach: resets the counter when the window expires.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT window_start, analysis_count FROM rate_limits WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
        now = datetime.now(timezone.utc)
        if row is None:
            conn.execute(
                "INSERT INTO rate_limits (installation_id, window_start, analysis_count) VALUES (?, ?, 1)",
                (installation_id, now.isoformat()),
            )
            return True
        window_start = datetime.fromisoformat(row["window_start"])
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=timezone.utc)
        elapsed = (now - window_start).total_seconds()
        if elapsed >= 3600:
            conn.execute(
                "UPDATE rate_limits SET window_start = ?, analysis_count = 1 WHERE installation_id = ?",
                (now.isoformat(), installation_id),
            )
            return True
        if row["analysis_count"] >= 20:
            return False
        conn.execute(
            "UPDATE rate_limits SET analysis_count = analysis_count + 1 WHERE installation_id = ?",
            (installation_id,),
        )
        return True


# --- Cost instrumentation ---

def save_llm_cost(analysis_id: int, input_tokens: int, output_tokens: int, cost_usd: float) -> None:
    """Save LLM token usage and cost to the analysis row."""
    with _connect() as conn:
        conn.execute(
            """
            UPDATE analyses
            SET llm_input_tokens = ?, llm_output_tokens = ?, llm_cost_usd = ?
            WHERE id = ?
            """,
            (input_tokens, output_tokens, cost_usd, analysis_id),
        )


def get_cost_stats() -> dict:
    """Return aggregate LLM cost statistics."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_analyses,
                COALESCE(AVG(llm_cost_usd), 0) AS average_cost_usd,
                COALESCE(SUM(llm_cost_usd), 0) AS total_cost_usd
            FROM analyses
            WHERE status = 'complete'
            """
        ).fetchone()
    return {
        "total_analyses": row["total_analyses"],
        "average_cost_usd": round(row["average_cost_usd"], 6),
        "total_cost_usd": round(row["total_cost_usd"], 6),
    }
