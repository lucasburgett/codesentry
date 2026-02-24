import logging
import os

import requests

logger = logging.getLogger(__name__)


def get_api_key():
    key = os.environ.get("API_KEY", "")
    if not key:
        raise RuntimeError("API_KEY environment variable is required")
    return key


def fetch_users():
    resp = requests.get(
        f"{os.environ.get('API_BASE_URL', '')}/users",
        headers={"Authorization": f"Bearer {get_api_key()}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def read_config(path):
    import json
    with open(path, "r") as f:
        return json.load(f)


def process_items(items, output_path):
    results = []
    for item in items:
        try:
            results.append(item.strip().upper())
        except AttributeError:
            logger.warning("Skipping non-string item: %s", item)
    with open(output_path, "w") as f:
        f.write("\n".join(results))
