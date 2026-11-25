"""F06 Security header misconfiguration: protective headers are absent.

Expected (vuln): no CSP / X-Frame-Options / X-Content-Type-Options.
Expected (fixed): all three present.
"""

from lab import banner, client

WANT = ["content-security-policy", "x-frame-options", "x-content-type-options"]


def run():
    banner("Missing security headers")
    c = client()
    h = {k.lower() for k in c.get("/api/health").headers}
    missing = [w for w in WANT if w not in h]
    print(f"missing headers: {missing}")
    return len(missing) == len(WANT)


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
