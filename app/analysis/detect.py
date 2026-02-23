"""Detect likely AI-authored files using commit and code heuristics."""

import re

# Heuristic 1: commit message patterns (case-insensitive)
_COMMIT_PATTERNS = [
    r"co-authored-by\s*:?\s*.*(?:copilot|cody|devin)",
    r"generated\s+(?:with|by|using)\s+(?:cursor|copilot|claude|chatgpt|gpt|aider|codeium|tabnine|windsurf|devin)",
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
    """Count added lines in a diff patch."""
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
    suspiciously uniform type hints, excessive inline comments.
    """
    if not patch:
        return 0.0

    score = 0.0

    if re.search(r"#\s*Step\s+\d+\s*:", patch, re.I):
        score += 0.15

    if re.search(r"TODO\s*:\s*Add\s+error\s+handling", patch, re.I):
        score += 0.15

    # Triple-quoted docstrings (Python) or JSDoc /** */ (JS/TS)
    if filename.endswith(".py") and '"""' in patch and "def " in patch:
        score += 0.15
    elif any(filename.endswith(ext) for ext in (".ts", ".tsx", ".js", ".jsx")):
        if "/**" in patch and "*/" in patch:
            score += 0.15

    # Uniform type hints
    if filename.endswith(".py"):
        if re.findall(r":\s*(?:int|str|bool|float|list|dict|Optional)\s*[,\)]", patch):
            typed_count = len(re.findall(r"\w+\s*:\s*(?:int|str|bool|float|list|dict|Optional)\b", patch))
            if typed_count >= 2:
                score += 0.15
    elif any(filename.endswith(ext) for ext in (".ts", ".tsx")):
        typed_count = len(re.findall(r"\w+\s*:\s*(?:number|string|boolean|Array|object)\b", patch))
        if typed_count >= 2:
            score += 0.15

    # Excessive inline comments narrating obvious code
    trivial_comments = re.findall(
        r"#\s*(?:import|define|set|create|initialize|return|get|check|handle)\s",
        patch, re.I,
    )
    if len(trivial_comments) >= 3:
        score += 0.3

    return min(score, 0.6)


def _heuristic3_score(file_dict: dict) -> float:
    """
    Large-change file signal.
    New files >100 added lines: +0.4
    Modified files >200 added lines: +0.3
    """
    patch = file_dict.get("patch", "")
    lines = _patch_line_count(patch)
    status = file_dict.get("status", "")

    if status == "added" and lines >= 100:
        return 0.4
    if status == "modified" and lines >= 200:
        return 0.3

    return 0.0


def detect_ai_files(
    files: list[dict], commit_messages: list[str] | list[dict]
) -> list[tuple[str, float]]:
    """
    Detect files likely AI-authored. Returns list of (filename, confidence).
    Uses three heuristics. Files with combined confidence >= 0.3 are flagged.

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
        if combined >= 0.3:
            result.append((f["filename"], round(min(combined, 1.0), 2)))

    return result
