"""Render the generated Markdown docs into a small static site for GitHub Pages.

Uses the `markdown` package (installed in the Pages workflow). Output goes to ``site/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import markdown  # provided in CI

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SITE = ROOT / "site"

PAGES = [
    ("index.md", "index.html", "Findings report"),
    ("zap-mapping.md", "zap-mapping.html", "ZAP mapping"),
    ("threat-model-file-upload.md", "threat-model.html", "Threat model"),
    ("review-checklist.md", "review-checklist.html", "Review checklist"),
    ("agent-report-vuln.md", "agent-report-vuln.html", "Agent report (vuln)"),
    ("agent-report-fixed.md", "agent-report-fixed.html", "Agent report (fixed)"),
]

STYLE = (
    "body{font:16px/1.6 system-ui,sans-serif;max-width:900px;margin:2rem auto;"
    "padding:0 1rem;color:#1a1a2e}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
    "code{background:#f3f3f7;padding:.1rem .3rem;border-radius:3px}nav a{margin-right:1rem}"
    "blockquote{border-left:4px solid #e63946;background:#fff5f5;padding:.5rem 1rem;margin:1rem 0}"
    "h1,h2{border-bottom:1px solid #eee;padding-bottom:.2rem}"
)


def nav() -> str:
    links = " ".join(f'<a href="{out}">{title}</a>' for _, out, title in PAGES)
    return f"<nav>{links}</nav><hr>"


def wrap(title: str, body: str) -> str:
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{title} — red-team-appsec-lab</title><style>{STYLE}</style></head>"
        f"<body>{nav()}{body}</body></html>"
    )


def main() -> int:
    SITE.mkdir(exist_ok=True)
    (SITE / ".nojekyll").write_text("", encoding="utf-8")
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc"])
    rendered = 0
    for src, out, title in PAGES:
        path = DOCS / src
        if not path.is_file():
            continue
        html = md.convert(path.read_text(encoding="utf-8"))
        md.reset()
        (SITE / out).write_text(wrap(title, html), encoding="utf-8")
        rendered += 1
    print(f"rendered {rendered} pages to site/")
    return 0 if rendered else 1


if __name__ == "__main__":
    sys.exit(main())
