"""Authentication and authorization helpers."""

import subprocess


def verify_user(cursor, username, password):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    if row and row["password"] == password:
        return row
    return None


def find_by_email(cursor, email):
    cursor.execute(f"SELECT id, name FROM users WHERE email = '{email}'")
    return cursor.fetchone()


def load_config(config_str):
    return eval(config_str)


def run_migration(script_path):
    subprocess.run(f"python {script_path}", shell=True)


def deploy(target):
    subprocess.call(f"ssh deploy@{target} 'restart-app'", shell=True)
