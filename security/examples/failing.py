"""Failing example for the secure pipeline (intentional).

Semgrep's rules in security/semgrep.yml are expected to flag this file. CI scans it in
the 'failing example' step to prove the scanners actually catch the patterns, then the
step is allowed to continue so the overall pipeline stays green.
"""


def bad_login(conn, username, password):
    # Expected hit: sql-string-concatenation
    return conn.execute(
        "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    ).fetchone()


def bad_render(body):
    # Expected hit: unescaped-html-response
    return f"<div>{body}</div>"


# Expected hit: hardcoded-weak-jwt-secret
SECRET = "secret"
