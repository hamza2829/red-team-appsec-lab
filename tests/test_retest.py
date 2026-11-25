"""Re-test harness: each finding is proven in vuln mode and proven fixed in fixed mode.

CI runs this file twice as a matrix (APP_MODE=vuln and APP_MODE=fixed). The same test
body asserts the exploit succeeds on the vulnerable build and fails on the fixed build,
so one test documents both the vulnerability and its remediation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacks"))

import pytest  # noqa: E402

from attacks import (  # noqa: E402
    agent_injection,
    agent_tool_abuse,
    headers,
    idor,
    leaked_key,
    rate_limit,
    sqli,
    stored_xss,
    weak_jwt,
)
from attacks.lab import FIXED  # noqa: E402

# finding id -> (module, human name)
FINDINGS = [
    ("F01", idor, "IDOR on GET /api/tickets/{id}"),
    ("F02", sqli, "SQL injection auth bypass"),
    ("F03", stored_xss, "Stored XSS on ticket render"),
    ("F04", weak_jwt, "Weak JWT secret token forgery"),
    ("F05", rate_limit, "Missing login rate limit"),
    ("F06", headers, "Security header misconfiguration"),
    ("F08", agent_tool_abuse, "Agent tool abuse / scope break"),
    ("F09", agent_injection, "Indirect prompt injection + approval bypass"),
]


@pytest.mark.parametrize("fid,module,name", FINDINGS, ids=[f[0] for f in FINDINGS])
def test_finding(fid, module, name):
    exploitable = module.run()
    if FIXED:
        assert not exploitable, f"{fid} {name}: fix did not hold — still exploitable in fixed mode"
    else:
        assert exploitable, f"{fid} {name}: expected to be exploitable in vuln mode"


def test_f07_leaked_key_history():
    """F07 is a git-history finding; the leak exists regardless of app mode."""
    assert leaked_key.run(), "F07: planted key should be recoverable from git history"
