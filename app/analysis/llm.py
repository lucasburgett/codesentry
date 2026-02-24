"""LLM behavioral summary using Claude API."""

import asyncio
import json
import logging
import os
import re

import anthropic
import tiktoken

logger = logging.getLogger(__name__)

_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 2048
_TOKEN_BUDGET = 4000
_COST_PER_1K_INPUT = 0.0008
_COST_PER_1K_OUTPUT = 0.004

_PROMPT_TEMPLATE = """\
You are a senior software engineer reviewing a pull request.
Below is a diff of code changes. Your job is to:
1. Write a 3-5 sentence plain-English summary of what this code \
actually does (what behavior it introduces or changes).
2. List 2-4 specific behavioral risks or edge cases that could \
fail in production that a reviewer might miss at a glance.
Be concrete. Reference actual variable names, functions, or \
conditions from the code. Do not summarize line by line.

Return ONLY valid JSON in this exact format:
{
  "summary": "...",
  "behavioral_flags": [
    {"flag": "...", "severity": "high|medium|low", "location": "filename:line"}
  ]
}

Code diff:
{diff_content}"""

_enc = tiktoken.get_encoding("cl100k_base")


def _count_tokens(text: str) -> int:
    return len(_enc.encode(text))


def _has_additions(patch: str) -> bool:
    """Return True if the patch contains any added lines."""
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            return True
    return False


def build_prompt(files: list[dict]) -> str | None:
    """Build token-limited prompt from AI-authored file diffs.

    Returns None if there are no meaningful additions to review.
    """
    if not files:
        return None

    patches_with_additions: list[tuple[str, str]] = []
    for f in files:
        patch = f.get("patch") or ""
        filename = f.get("filename", "unknown")
        if patch and _has_additions(patch):
            patches_with_additions.append((filename, patch))

    if not patches_with_additions:
        return None

    template_tokens = _count_tokens(
        _PROMPT_TEMPLATE.replace("{diff_content}", "")
    )
    remaining = _TOKEN_BUDGET - template_tokens

    diff_blocks: list[str] = []
    files_included = 0
    for filename, patch in patches_with_additions:
        header = f"--- {filename} ---\n"
        block = header + patch + "\n"
        block_tokens = _count_tokens(block)

        if block_tokens <= remaining:
            diff_blocks.append(block)
            remaining -= block_tokens
            files_included += 1
        else:
            lines = block.splitlines(keepends=True)
            truncated: list[str] = []
            used = 0
            for line in lines:
                line_tokens = _count_tokens(line)
                if used + line_tokens > remaining:
                    break
                truncated.append(line)
                used += line_tokens
            if truncated:
                truncated.append(f"\n... (truncated)\n")
                diff_blocks.append("".join(truncated))
                files_included += 1
            remaining = 0
            break

    skipped = len(patches_with_additions) - files_included
    if skipped > 0:
        diff_blocks.append(f"({skipped} more file(s) truncated)\n")

    if not diff_blocks:
        return None

    diff_content = "".join(diff_blocks)
    return _PROMPT_TEMPLATE.replace("{diff_content}", diff_content)


async def call_claude(prompt: str) -> dict:
    """Call Claude Haiku and return the raw response text.

    Raises ValueError if ANTHROPIC_API_KEY is not set.
    Returns {"error": "llm_unavailable"} on API failures.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

    client = anthropic.AsyncAnthropic(api_key=api_key)

    for attempt in range(2):
        try:
            response = await client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )

            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            cost = (
                (input_tokens / 1000) * _COST_PER_1K_INPUT
                + (output_tokens / 1000) * _COST_PER_1K_OUTPUT
            )
            logger.info(
                "LLM cost: input=%d tokens, output=%d tokens, est=$%.4f",
                input_tokens, output_tokens, cost,
            )

            if not response.content:
                return {"error": "llm_unavailable"}

            return {
                "text": response.content[0].text,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost,
            }

        except anthropic.RateLimitError:
            if attempt == 0:
                logger.warning("Claude rate-limited, retrying in 2s...")
                await asyncio.sleep(2)
                continue
            logger.error("Claude rate-limited after retry")
            return {"error": "llm_unavailable"}
        except (anthropic.APITimeoutError, anthropic.APIError) as exc:
            logger.error("Claude API error: %s", exc)
            return {"error": "llm_unavailable"}
        except Exception as exc:
            logger.error("Unexpected error calling Claude: %s", exc)
            return {"error": "llm_unavailable"}

    return {"error": "llm_unavailable"}


def parse_llm_response(raw: str) -> dict:
    """Parse Claude's response into structured summary + flags.

    Handles valid JSON, JSON in markdown code blocks, truncated JSON,
    and plain text fallback.
    """
    cleaned = _strip_markdown_fencing(raw)

    parsed = _try_parse_json(cleaned)
    if parsed is None:
        match = re.search(r"\{[\s\S]*\}", cleaned)
        if match:
            parsed = _try_parse_json(match.group())
            if parsed is None:
                parsed = _try_repair_truncated_json(match.group())

    if parsed is None:
        fallback = _strip_markdown_fencing(raw)
        return {"summary": fallback[:500], "behavioral_flags": []}

    summary = parsed.get("summary", "")
    flags_raw = parsed.get("behavioral_flags", [])
    if not isinstance(flags_raw, list):
        flags_raw = []

    flags = []
    for f in flags_raw:
        if not isinstance(f, dict):
            continue
        flags.append({
            "flag": f.get("flag", ""),
            "severity": f.get("severity", "medium"),
            "location": f.get("location", ""),
        })

    return {"summary": summary, "behavioral_flags": flags}


def _strip_markdown_fencing(text: str) -> str:
    """Remove markdown code block fencing (```json ... ```) from text."""
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    text = re.sub(r"\n?```\s*$", "", text.strip())
    return text.strip()


def _try_repair_truncated_json(text: str) -> dict | None:
    """Attempt to extract 'summary' from truncated JSON.

    When Claude hits max_tokens, the JSON is cut mid-stream. We try to
    at least salvage the summary field.
    """
    m = re.search(r'"summary"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
    if m:
        return {"summary": m.group(1), "behavioral_flags": []}
    return None


def _try_parse_json(text: str) -> dict | None:
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def filter_flags_by_evidence(
    behavioral_flags: list[dict], semgrep_findings: list[dict]
) -> list[dict]:
    """Apply evidence-based gating to LLM behavioral flags.

    When Semgrep finds nothing, the LLM is speculating — only surface high
    severity flags.  When Semgrep finds warnings but no errors, surface high
    and medium.  When Semgrep finds errors, keep everything.

    If fewer than 2 flags survive filtering, suppress the entire section to
    avoid noisy single-flag reports.
    """
    if not behavioral_flags:
        return []

    has_errors = any(f.get("severity") == "error" for f in semgrep_findings)
    has_findings = bool(semgrep_findings)

    if has_errors:
        filtered = list(behavioral_flags)
    elif has_findings:
        filtered = [f for f in behavioral_flags if f.get("severity") in ("high", "medium")]
    else:
        filtered = [f for f in behavioral_flags if f.get("severity") == "high"]

    if len(filtered) < 2:
        return []

    return filtered


def deduplicate_flags(
    llm_flags: list[dict], semgrep_findings: list[dict]
) -> list[dict]:
    """Remove LLM flags that overlap with Semgrep findings within 3 lines."""
    if not llm_flags or not semgrep_findings:
        return list(llm_flags)

    result = []
    for flag in llm_flags:
        location = flag.get("location", "")
        parts = location.rsplit(":", 1)
        if len(parts) != 2:
            result.append(flag)
            continue

        flag_file, line_str = parts
        try:
            flag_line = int(line_str)
        except ValueError:
            result.append(flag)
            continue

        is_duplicate = any(
            f["file_path"] == flag_file and abs(f["line_start"] - flag_line) <= 3
            for f in semgrep_findings
        )
        if not is_duplicate:
            result.append(flag)

    return result
