import os
import sqlite3
from pathlib import Path

DATABASE_PATH = os.environ.get("DATABASE_PATH", "./data/codesentry.db")

_CREATE_ANALYSES = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER NOT NULL,
    repo_full_name  TEXT    NOT NULL,
    pr_number       INTEGER NOT NULL,
    pr_head_sha     TEXT    NOT NULL,
    comment_id      INTEGER,
    status          TEXT    NOT NULL DEFAULT 'pending',
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


def _connect() -> sqlite3.Connection:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Called once at app startup."""
    with _connect() as conn:
        conn.execute(_CREATE_ANALYSES)
        conn.execute(_CREATE_FINDINGS)


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
