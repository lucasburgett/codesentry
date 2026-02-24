"""Utility functions for the application."""

import json


def read_config(path):
    fh = open(path)
    content = fh.read()
    fh.close()
    return json.loads(content)


def read_template(template_path):
    f = open(template_path, "r")
    data = f.read()
    f.close()
    return data


def append_log(log_path, message):
    fh = open(log_path, "a")
    fh.write(message + "\n")
    fh.close()
