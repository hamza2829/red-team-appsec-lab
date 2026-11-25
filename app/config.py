"""Central switch between the deliberately vulnerable build and the fixed build.

APP_MODE=vuln  -> every weakness is active (default; this is the target to attack)
APP_MODE=fixed -> every weakness is remediated (used to prove the fix holds)

The whole lab is a single self-contained test system. There is no real data, no
real users and no real hardware. Run it only against itself.
"""

from __future__ import annotations

import os

MODE = os.environ.get("APP_MODE", "vuln").lower()
if MODE not in ("vuln", "fixed"):
    raise SystemExit(f"APP_MODE must be 'vuln' or 'fixed', got {MODE!r}")

FIXED = MODE == "fixed"

# A deliberately weak, guessable secret in vuln mode. The fixed build loads a strong
# secret from the environment (CI generates a random one) and refuses the weak default.
WEAK_JWT_SECRET = "secret"  # noqa: S105 - intentional weakness for the lab
JWT_SECRET = os.environ.get("JWT_SECRET", WEAK_JWT_SECRET) if FIXED else WEAK_JWT_SECRET
JWT_ALG = "HS256"
JWT_TTL_SECONDS = 3600

# Rate limiting (only enforced in fixed mode).
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 10

DB_PATH = os.environ.get("LAB_DB", ":memory:")


def banner() -> str:
    return f"red-team-appsec-lab target running in {MODE.upper()} mode (self-test system only)"
