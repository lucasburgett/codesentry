import requests
import subprocess

api_key = "sk-live-abc123456789"


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def risky_request():
    resp = requests.get("https://api.example.com/data")
    data = resp.json()
    return data


def read_config():
    fh = open("config.txt")
    content = fh.read()
    fh.close()
    return content


def do_something():
    try:
        result = 1 / 0
    except:
        pass


def run_command(cmd):
    subprocess.run(cmd, shell=True)


def dangerous(code):
    eval(code)


def append_item(items=[]):
    items.append(1)
    return items


def validate(value):
    assert value > 0
