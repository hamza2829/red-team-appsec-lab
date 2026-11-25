"""Passing example for the secure pipeline: clean, parameterised, escaped code.

Semgrep and the linters should report zero findings here. It mirrors the fixed build's
approach and exists so CI has a positive control that must stay green.
"""

from __future__ import annotations

import html
import os
import sqlite3


def safe_login(conn: sqlite3.Connection, username: str, password: str):
    return conn.execute(
        "SELECT id FROM users WHERE username = ? AND password = ?", (username, password)
    ).fetchone()


def safe_render(title: str, body: str) -> str:
    return f"<h1>{html.escape(title)}</h1><div>{html.escape(body)}</div>"


def load_secret() -> str:
    secret = os.environ["JWT_SECRET"]
    if len(secret) < 16:
        raise ValueError("signing secret too short")
    return secret
