"""A file with a mix of normal and slightly unusual patterns."""

import sys


def greet(name: str) -> str:
    return f"Hello, {name}!"


def calculate(a: int, b: int) -> int:
    return a + b


GREETING = greet("world")
RESULT = calculate(1, 2)

if __name__ == "__main__":
    print(GREETING, RESULT)
    sys.exit(0)
