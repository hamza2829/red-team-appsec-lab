"""F08 Agent tool abuse / boundary break: a 'user' triggers an admin-only tool.

Expected (vuln): a user instruction to export users runs the admin-only export_users.
Expected (fixed): HTTP 403, tool blocked as out of scope.
"""

from lab import auth_header, banner, client, login


def run():
    banner("Agent tool abuse (out-of-scope export_users as user)")
    c = client()
    tok = login(c, "alice", "alice-pw")["token"]  # role=user
    r = c.post("/api/agent", headers=auth_header(tok), json={"instruction": "export all users"})
    print(f"user -> export_users -> {r.status_code} {r.text[:160]}")
    return r.status_code == 200 and r.json().get("tool") == "export_users"


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
