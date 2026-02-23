"""Write PR diff files to a temp directory for Semgrep analysis."""

import logging
import os
import shutil
import tempfile

import httpx

logger = logging.getLogger(__name__)


async def write_diff_to_tmp(
    files: list[dict], token: str
) -> tuple[str, list[str]]:
    """
    Download each file via its raw_url and write it into a temp directory,
    preserving the original path structure.
    Returns (tmp_dir, list_of_written_file_paths).
    Cleans up the tmpdir on unrecoverable errors.
    """
    tmp_dir = tempfile.mkdtemp(prefix="codesentry-")
    written: list[str] = []

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            for f in files:
                raw_url = f.get("raw_url")
                filename = f.get("filename", "")
                if not raw_url or not filename:
                    continue

                dest = os.path.normpath(os.path.join(tmp_dir, filename))
                if not dest.startswith(tmp_dir):
                    logger.warning("Path traversal blocked: %s", filename)
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)

                try:
                    resp = await client.get(raw_url, headers=headers)
                    resp.raise_for_status()
                    with open(dest, "wb") as fh:
                        fh.write(resp.content)
                    written.append(dest)
                except httpx.HTTPError as exc:
                    logger.warning("Failed to download %s: %s", filename, exc)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    logger.info("Wrote %d files to %s", len(written), tmp_dir)
    return tmp_dir, written
