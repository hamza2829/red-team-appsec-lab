"""F05 Missing rate limit: brute-force login is not throttled.

Expected (vuln): 50 rapid login attempts all get through (no 429).
Expected (fixed): throttled with HTTP 429 after the window max.
"""

from lab import banner, client


def run():
    banner("Missing rate limit on POST /api/login")
    c = client()
    codes = [
        c.post("/api/login", json={"username": "x", "password": str(i)}).status_code
        for i in range(50)
    ]
    throttled = codes.count(429)
    print(f"attempts=50 throttled(429)={throttled}")
    return throttled == 0


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
