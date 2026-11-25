"""JWT + cookie session issuing and verification.

VULN build: signs with a weak secret ("secret") so tokens are forgeable, and in that
mode also accepts tokens with alg=none. FIXED build: strong secret from the
environment, HS256 only, alg confusion rejected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from .config import FIXED, JWT_ALG, JWT_SECRET, JWT_TTL_SECONDS


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _sign(signing_input: bytes) -> str:
    return _b64(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())


def issue_token(user_id: int, role: str) -> str:
    header = {"alg": JWT_ALG, "typ": "JWT"}
    payload = {"sub": user_id, "role": role, "exp": int(time.time()) + JWT_TTL_SECONDS}
    segments = [
        _b64(json.dumps(header, separators=(",", ":")).encode()),
        _b64(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    segments.append(_sign(".".join(segments).encode()))
    return ".".join(segments)


class InvalidToken(Exception):
    pass


def verify_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_unb64(header_b64))
        payload = json.loads(_unb64(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("malformed token") from exc

    alg = header.get("alg")
    if not FIXED and alg == "none":
        # VULN: alg confusion — unsigned tokens are accepted.
        return payload
    if alg != JWT_ALG:
        raise InvalidToken(f"unexpected alg {alg!r}")

    expected = _sign(f"{header_b64}.{payload_b64}".encode())
    if not hmac.compare_digest(expected, signature):
        raise InvalidToken("bad signature")
    if payload.get("exp", 0) < time.time():
        raise InvalidToken("expired")
    return payload
