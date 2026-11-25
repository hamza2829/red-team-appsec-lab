# Security review checklist (pre-merge)

Use for any change touching auth, data access, rendering, the agent, or dependencies.
A reviewer ticks every item or records why it does not apply.

## Access control
- [ ] Every object read/write checks ownership or role (no IDOR — see F01).
- [ ] New agent tools declare a role scope and are denied out of scope (F08).

## Injection & output
- [ ] All SQL uses parameters, no string building (F02).
- [ ] All user data is escaped on output; CSP present (F03, F06).
- [ ] Retrieved/stored content is never treated as agent instructions (F09).

## Auth & secrets
- [ ] Tokens signed with a strong env secret; alg pinned; alg=none rejected (F04).
- [ ] Auth endpoints are rate limited (F05).
- [ ] No secrets in code or history; gitleaks passes (F07).

## Pipeline
- [ ] Semgrep, gitleaks, pip-audit run and were reviewed.
- [ ] SBOM regenerated if dependencies changed.
- [ ] New vulnerability classes get a vuln/fixed re-test in `tests/test_retest.py`.

## AI agent
- [ ] Destructive tools require out-of-band human approval (no in-band bypass).
- [ ] Prompt-injection and tool-abuse probes added to `agent/`.
