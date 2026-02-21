"""Detect likely AI-authored files using commit and code heuristics."""

import re

# Heuristic 1: commit message patterns (case-insensitive)
_COMMIT_PATTERNS = [
    r"co-authored-by\s*:?\s*.*copilot",
    r"generated\s+(?:with|by|using)\s+(?:cursor|copilot|claude|chatgpt|gpt)",
    r"ai[.\s-]?generated",
    r"vibe[.\s-]?cod",
]
_COMMIT_RE = re.compile("|".join(f"({p})" for p in _COMMIT_PATTERNS), re.I)


def _commit_heuristic_matches(commit_messages: list[str]) -> bool:
    """Check if any commit message matches AI-related patterns."""
    for msg in commit_messages:
        if msg and _COMMIT_RE.search(msg):
            return True
    return False


def _patch_line_count(patch: str) -> int:
    """Count added lines in a diff patch (for new files, this is the file size)."""
    if not patch:
        return 0
    count = 0
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            count += 1
    return count


def _heuristic2_score(patch: str, filename: str) -> float:
    """
    Code style signals: each adds 0.15, capped at 0.6.
    Signals: triple-quoted docstrings, # Step N:, TODO: Add error handling,
    suspiciously uniform type hints.
    """
    if not patch:
        return 0.0

    score = 0.0

    # # Step N: style comments
    if re.search(r"#\s*Step\s+\d+\s*:", patch, re.I):
        score += 0.15

    # TODO: Add error handling (or similar)
    if re.search(r"TODO\s*:\s*Add\s+error\s+handling", patch, re.I):
        score += 0.15

    # Triple-quoted docstrings (Python) or JSDoc /** */ (JS/TS)
    if filename.endswith(".py") and '"""' in patch and "def " in patch:
        score += 0.15
    elif any(filename.endswith(ext) for ext in (".ts", ".tsx", ".js", ".jsx")):
        if "/**" in patch and "*/" in patch:
            score += 0.15

    # Uniform type hints - multiple typed params (Python or TypeScript)
    if filename.endswith(".py"):
        if re.findall(r":\s*(?:int|str|bool|float|list|dict|Optional)\s*[,\)]", patch):
            typed_count = len(re.findall(r"\w+\s*:\s*(?:int|str|bool|float|list|dict|Optional)\b", patch))
            if typed_count >= 2:
                score += 0.15
    elif any(filename.endswith(ext) for ext in (".ts", ".tsx")):
        typed_count = len(re.findall(r"\w+\s*:\s*(?:number|string|boolean|Array|object)\b", patch))
        if typed_count >= 2:
            score += 0.15

    return min(score, 0.6)


def _heuristic3_score(file_dict: dict) -> float:
    """New files >100 lines that appear complete: +0.4."""
    if file_dict.get("status") != "added":
        return 0.0

    patch = file_dict.get("patch", "")
    lines = _patch_line_count(patch)
    if lines < 100:
        return 0.0

    # "Appear complete" - simple check: has multiple logical blocks (functions/classes)
    # New file with 100+ lines of code is a strong signal
    return 0.4


def detect_ai_files(
    files: list[dict], commit_messages: list[str] | list[dict]
) -> list[tuple[str, float]]:
    """
    Detect files likely AI-authored. Returns list of (filename, confidence).
    Uses three heuristics. Files with combined confidence >= 0.4 are flagged.

    commit_messages: list of strings, or list of dicts with "message" key.
    """
    msgs: list[str] = []
    for c in commit_messages:
        if isinstance(c, str):
            msgs.append(c)
        elif isinstance(c, dict) and "message" in c:
            msgs.append(c["message"])

    result: list[tuple[str, float]] = []

    # Heuristic 1: commit message signals → flag ALL files with 0.9
    if _commit_heuristic_matches(msgs):
        for f in files:
            result.append((f["filename"], 0.9))
        return result

    # Heuristics 2 and 3: per-file
    for f in files:
        h2 = _heuristic2_score(f.get("patch", ""), f.get("filename", ""))
        h3 = _heuristic3_score(f)
        combined = h2 + h3
        if combined >= 0.4:
            result.append((f["filename"], round(min(combined, 1.0), 2)))

    return result
