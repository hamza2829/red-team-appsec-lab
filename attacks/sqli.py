"""F02 SQL injection: auth bypass in the login query.

Expected (vuln): username ' OR '1'='1' -- logs in as the first user without a password.
Expected (fixed): HTTP 401.
"""

from lab import banner, client


def run():
    banner("SQLi auth bypass on POST /api/login")
    c = client()
    payload = {"username": "' OR '1'='1' -- ", "password": "x"}
    r = c.post("/api/login", json=payload)
    print(f"login with {payload['username']!r} -> {r.status_code} {r.text[:120]}")
    return r.status_code == 200


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
