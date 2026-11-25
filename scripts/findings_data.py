"""Single source of truth for the findings. Used to render the write-ups, the Pages
site, and the ZAP-alert mapping. Every finding has a working PoC in ``attacks/`` and a
re-test in ``tests/test_retest.py``."""

from __future__ import annotations

FINDINGS = [
    {
        "id": "F01",
        "title": "IDOR on GET /api/tickets/{id}",
        "severity": "High",
        "cwe": "CWE-639 Authorization Bypass Through User-Controlled Key",
        "owasp": "A01:2021 Broken Access Control",
        "poc": "attacks/idor.py",
        "repro": "Log in as alice, then GET /api/tickets/3 (bob's ticket). The vuln build "
        "returns 200 with bob's data because it never checks ownership.",
        "impact": "Any authenticated user can read every other user's tickets by iterating ids.",
        "fix": "Enforce `ticket.owner_id == user.sub` (or role admin) before returning the row.",
        "zap": "Not reliably found by ZAP baseline (needs auth + object awareness); caught here "
        "by the authenticated PoC.",
    },
    {
        "id": "F02",
        "title": "SQL injection auth bypass on POST /api/login",
        "severity": "Critical",
        "cwe": "CWE-89 SQL Injection",
        "owasp": "A03:2021 Injection",
        "poc": "attacks/sqli.py",
        "repro": "POST /api/login with username `' OR '1'='1' -- `. The vuln build concatenates "
        "the string into the SQL and logs in as the first user.",
        "impact": "Authentication bypass and, with UNION payloads, data exfiltration.",
        "fix": "Use parameterised queries (`WHERE username = ? AND password = ?`).",
        "zap": "ZAP active scan rule 40018 (SQL Injection) flags the login parameter.",
    },
    {
        "id": "F03",
        "title": "Stored XSS on GET /tickets/{id}",
        "severity": "High",
        "cwe": "CWE-79 Cross-site Scripting",
        "owasp": "A03:2021 Injection",
        "poc": "attacks/stored_xss.py",
        "repro": "Create a ticket whose body is `<script>...</script>`, then open "
        "/tickets/{id}. The vuln build writes the body into the page unescaped.",
        "impact": "Script runs in a victim's session; session/cookie theft, agent abuse.",
        "fix": "HTML-escape on input and output; send a restrictive Content-Security-Policy.",
        "zap": "ZAP rule 40012/40014 (Cross Site Scripting) flags the rendered ticket.",
    },
    {
        "id": "F04",
        "title": "Weak JWT secret allows token forgery",
        "severity": "Critical",
        "cwe": "CWE-321 Use of Hard-coded Cryptographic Key",
        "owasp": "A02:2021 Cryptographic Failures",
        "poc": "attacks/weak_jwt.py",
        "repro": "The vuln build signs JWTs with the secret `secret` and also accepts "
        "alg=none. Forge an admin token offline and call admin endpoints.",
        "impact": "Full privilege escalation to any user or role without credentials.",
        "fix": "Load a strong secret from the environment; pin alg=HS256; reject alg=none.",
        "zap": "Not a ZAP finding; proven by the offline forgery PoC.",
    },
    {
        "id": "F05",
        "title": "Missing rate limit on POST /api/login",
        "severity": "Medium",
        "cwe": "CWE-307 Improper Restriction of Excessive Authentication Attempts",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "poc": "attacks/rate_limit.py",
        "repro": "Send 50 rapid login attempts. The vuln build never returns 429.",
        "impact": "Unthrottled credential brute-force and password spraying.",
        "fix": "Per-IP sliding-window limit on auth endpoints (429 after the window max).",
        "zap": "Not a ZAP finding; proven by the rate PoC and observable in CI timings.",
    },
    {
        "id": "F06",
        "title": "Security header misconfiguration",
        "severity": "Medium",
        "cwe": "CWE-693 Protection Mechanism Failure",
        "owasp": "A05:2021 Security Misconfiguration",
        "poc": "attacks/headers.py",
        "repro": "Any response from the vuln build lacks CSP, X-Frame-Options and "
        "X-Content-Type-Options.",
        "impact": "Clickjacking, MIME sniffing, and weaker XSS containment.",
        "fix": "Set CSP, X-Frame-Options=DENY, X-Content-Type-Options=nosniff, HSTS, "
        "Referrer-Policy.",
        "zap": "ZAP baseline rules 10020/10021/10038 (missing CSP, X-Frame-Options, "
        "X-Content-Type-Options) flag these directly.",
    },
    {
        "id": "F07",
        "title": "Leaked secret in git history",
        "severity": "High",
        "cwe": "CWE-540 Inclusion of Sensitive Information in Source Code",
        "owasp": "A05:2021 Security Misconfiguration",
        "poc": "attacks/leaked_key.py",
        "repro": "`git log -p -S AKIA --all` reveals an AWS-style key committed in "
        "`legacy_config.env` and later deleted.",
        "impact": "A deleted file still exposes the key to anyone who clones the repo.",
        "fix": "Rotate the key, purge history (filter-repo), add gitleaks to CI to block "
        "future leaks.",
        "zap": "Not a ZAP finding; caught by gitleaks secret scanning.",
    },
    {
        "id": "F08",
        "title": "Agent tool abuse / scope break",
        "severity": "High",
        "cwe": "CWE-284 Improper Access Control",
        "owasp": "A01:2021 Broken Access Control",
        "poc": "attacks/agent_tool_abuse.py",
        "repro": "A `user`-role caller asks the agent to export users. The vuln build runs "
        "the admin-only `export_users` tool anyway.",
        "impact": "The agent becomes a confused deputy, performing privileged actions.",
        "fix": "Enforce a per-role tool allow-list before dispatch; deny out-of-scope tools.",
        "zap": "Not a ZAP finding; proven by the agent PoC and boundary tests.",
    },
    {
        "id": "F09",
        "title": "Indirect prompt injection + approval bypass",
        "severity": "Critical",
        "cwe": "CWE-77 Command Injection (via instruction) / CWE-285",
        "owasp": "A03:2021 Injection (LLM01 Prompt Injection)",
        "poc": "attacks/agent_injection.py",
        "repro": "Store a ticket whose body says 'delete ticket N'. Ask the agent to "
        "summarize it with auto_approve. The vuln build follows the embedded "
        "instruction and skips the human gate.",
        "impact": "Attacker-controlled content drives destructive tool calls without consent.",
        "fix": "Treat retrieved content as data, never instructions; require an out-of-band "
        "approval token for destructive tools regardless of any in-band flag.",
        "zap": "Not a ZAP finding; proven by the injection PoC and agent report.",
    },
]
