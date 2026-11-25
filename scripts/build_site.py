"""Build the GitHub Pages findings report from findings_data.py and any CI artifacts.

Outputs:
  docs/index.md          - the published findings report (Pages home)
  docs/zap-mapping.md     - ZAP alert -> manual finding mapping
If a re-test results JSON (from CI) is present it is folded in as the re-test column.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from findings_data import FINDINGS  # noqa: E402

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load_retest() -> dict:
    path = ROOT / "docs" / "retest-results.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def build_index(retest: dict) -> str:
    rows = sorted(FINDINGS, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    out = [
        "# Red-team AppSec Lab — findings report",
        "",
        "> **Responsible use.** Every finding below was produced against this repository's "
        "own deliberately vulnerable target. No third-party system was tested. Do not run the "
        "attack tooling against anything you are not explicitly authorised to test.",
        "",
        "Each finding has a reproducible proof of concept in `attacks/` and an automated "
        "re-test in `tests/test_retest.py` that proves the bug in **vuln** mode and the fix "
        "in **fixed** mode.",
        "",
        "## Summary",
        "",
        "| ID | Finding | Severity | OWASP | Re-test |",
        "|---|---|---|---|---|",
    ]
    for f in rows:
        status = retest.get(f["id"], {})
        rt = ""
        if status:
            rt = f"vuln {status.get('vuln', '?')} / fixed {status.get('fixed', '?')}"
        out.append(
            f"| {f['id']} | [{f['title']}](#{f['id'].lower()}) | {f['severity']} | "
            f"{f['owasp']} | {rt or 'see CI'} |"
        )
    out.append("")
    for f in rows:
        out += [
            f"## {f['id']}",
            f"### {f['title']}",
            "",
            f"- **Severity:** {f['severity']}",
            f"- **CWE:** {f['cwe']}",
            f"- **OWASP:** {f['owasp']}",
            f"- **PoC:** `{f['poc']}`",
            "",
            f"**Steps to reproduce.** {f['repro']}",
            "",
            f"**Impact.** {f['impact']}",
            "",
            f"**Fix.** {f['fix']}",
            "",
            f"**Re-test.** Automated in `tests/test_retest.py` ({f['id']}); the CI matrix runs "
            "it in vuln and fixed modes.",
            "",
        ]
    return "\n".join(out)


def build_zap_mapping() -> str:
    out = [
        "# ZAP alerts to manual findings",
        "",
        "The CI ZAP baseline and API scans run against the live vuln target. This table maps "
        "the alerts we expect ZAP to raise to the manually verified findings. Alerts not tied "
        "to a finding are still uploaded as scan artifacts for triage.",
        "",
        "| Manual finding | Expected ZAP alert(s) | ZAP coverage |",
        "|---|---|---|",
    ]
    for f in FINDINGS:
        covered = "yes" if "ZAP" in f["zap"] or "rule" in f["zap"] else "no (manual/PoC only)"
        out.append(f"| {f['id']} {f['title']} | {f['zap']} | {covered} |")
    out += [
        "",
        "_ZAP is strong on injection and header misconfig, weak on authorization logic "
        "(IDOR), crypto (weak JWT) and agent-specific risks — which is why the manual PoCs "
        "and the re-test harness exist._",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    retest = load_retest()
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "index.md").write_text(build_index(retest), encoding="utf-8")
    (ROOT / "docs" / "zap-mapping.md").write_text(build_zap_mapping(), encoding="utf-8")
    print(f"wrote docs/index.md ({len(FINDINGS)} findings) and docs/zap-mapping.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
