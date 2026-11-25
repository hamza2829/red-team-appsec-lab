"""SQLite storage with seeded users and tickets.

The vulnerable build builds some queries by string concatenation (SQL injection);
the fixed build uses parameterised queries everywhere.
"""

from __future__ import annotations

import sqlite3
import threading

from .config import FIXED

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

SEED_USERS = [
    # id, username, password, role
    (1, "alice", "alice-pw", "user"),
    (2, "bob", "bob-pw", "user"),
    (3, "admin", "admin-pw", "admin"),
]

SEED_TICKETS = [
    # id, owner_id, title, body
    (1, 1, "Alice laptop", "Alice cannot connect to the VPN."),
    (2, 1, "Alice badge", "Alice lost her building badge."),
    (3, 2, "Bob monitor", "Bob needs a second monitor."),
    (4, 3, "Admin note", "Internal: rotate the signing key quarterly."),
]


def get_conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(":memory:", check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _init(_conn)
        return _conn


def reset() -> None:
    """Drop the in-memory DB so each test/PoC run starts from the seed data."""
    global _conn
    with _lock:
        _conn = None


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT
        );
        CREATE TABLE tickets (
            id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT
        );
        """
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", SEED_USERS)
    conn.executemany("INSERT INTO tickets VALUES (?,?,?,?)", SEED_TICKETS)
    conn.commit()


def find_user(username: str, password: str) -> sqlite3.Row | None:
    conn = get_conn()
    if FIXED:
        cur = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
        )
    else:
        # VULN: SQL injection — user input concatenated straight into the query.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        cur = conn.execute(query)
    return cur.fetchone()


def get_user(user_id: int) -> sqlite3.Row | None:
    return get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_ticket(ticket_id: int) -> sqlite3.Row | None:
    return get_conn().execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()


def list_tickets(owner_id: int) -> list[sqlite3.Row]:
    return get_conn().execute("SELECT * FROM tickets WHERE owner_id = ?", (owner_id,)).fetchall()


def add_ticket(owner_id: int, title: str, body: str) -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO tickets (owner_id, title, body) VALUES (?,?,?)", (owner_id, title, body)
    )
    conn.commit()
    return int(cur.lastrowid)
