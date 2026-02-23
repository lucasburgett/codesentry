import os
import logging

logger = logging.getLogger(__name__)

API_KEY = os.environ["API_KEY"]


def get_user(db, user_id: int) -> dict:
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return dict(row.fetchone())


def fetch_data(url: str) -> dict:
    import requests

    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()


def read_config(path: str) -> str:
    with open(path) as f:
        return f.read()


def safe_divide(a: float, b: float) -> float:
    try:
        return a / b
    except ZeroDivisionError:
        logger.error("Division by zero: a=%s, b=%s", a, b)
        return 0.0
