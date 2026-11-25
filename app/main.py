"""Deliberately vulnerable ticketing app + API + mock AI agent.

This is a self-contained security lab target. It ships two builds selected by
``APP_MODE`` (see ``app.config``): ``vuln`` (default, every weakness active) and
``fixed``. Attack scripts and the re-test harness drive both builds.

THIS IS MY OWN TEST SYSTEM. It contains intentional vulnerabilities. Do not deploy it,
do not expose it to a network, and never point the attack tooling at anything else.
"""

from __future__ import annotations

import html
import time
from collections import defaultdict, deque

from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from . import agent as agent_mod
from . import auth, db
from .config import FIXED, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, banner

app = FastAPI(title="red-team-appsec-lab target", description=banner())

_HITS: dict[str, deque] = defaultdict(deque)
# A per-process approval store for destructive agent actions (out-of-band token).
_APPROVALS: dict[str, dict] = {}
_PENDING_COUNTER = {"n": 0}


@app.middleware("http")
async def security_controls(request: Request, call_next):
    # Rate limiting is only wired up in the fixed build (missing-rate-limit weakness).
    if FIXED:
        ip = request.client.host if request.client else "test"
        now = time.time()
        hits = _HITS[ip]
        while hits and hits[0] < now - RATE_LIMIT_WINDOW:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_MAX and request.url.path == "/api/login":
            return JSONResponse({"detail": "rate limited"}, status_code=429)
        hits.append(now)

    response = await call_next(request)

    if FIXED:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=63072000"
        if "server" in response.headers:
            del response.headers["server"]
    # VULN build: no security headers are set at all.
    return response


def _current_user(authorization: str | None, session: str | None) -> dict:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    elif session:
        token = session
    if not token:
        raise HTTPException(401, "not authenticated")
    try:
        return auth.verify_token(token)
    except auth.InvalidToken as exc:
        raise HTTPException(401, str(exc)) from exc


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "fixed" if FIXED else "vuln"}


@app.post("/api/login")
def login(payload: dict, response: Response):
    row = db.find_user(payload.get("username", ""), payload.get("password", ""))
    if not row:
        raise HTTPException(401, "invalid credentials")
    token = auth.issue_token(row["id"], row["role"])
    response.set_cookie("session", token, httponly=FIXED, samesite="strict" if FIXED else "lax")
    return {"token": token, "user_id": row["id"], "role": row["role"]}


@app.get("/api/tickets/{ticket_id}")
def read_ticket(
    ticket_id: int,
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
):
    user = _current_user(authorization, session)
    ticket = db.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(404, "no such ticket")
    # VULN build: no ownership check -> IDOR. Fixed build enforces owner/admin.
    if FIXED and ticket["owner_id"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(403, "forbidden")
    return dict(ticket)


@app.get("/api/tickets")
def my_tickets(
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
):
    user = _current_user(authorization, session)
    return [dict(r) for r in db.list_tickets(user["sub"])]


@app.post("/api/tickets")
def create_ticket(
    payload: dict,
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
):
    user = _current_user(authorization, session)
    body = payload.get("body", "")
    title = payload.get("title", "")
    if FIXED:
        # Store-safe: escape on the way in so rendering cannot execute script.
        body = html.escape(body)
        title = html.escape(title)
    tid = db.add_ticket(user["sub"], title, body)
    return {"id": tid}


@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def render_ticket(ticket_id: int):
    ticket = db.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(404, "no such ticket")
    title, body = ticket["title"], ticket["body"]
    if FIXED:
        title, body = html.escape(title), html.escape(body)
    # VULN build: raw ticket body is written into the page -> stored XSS.
    return f"<!doctype html><html><body><h1>{title}</h1><div id=body>{body}</div></body></html>"


@app.post("/api/agent")
def run_agent(
    payload: dict,
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
):
    user = _current_user(authorization, session)
    instruction = payload.get("instruction", "")
    ref = payload.get("ticket_id")
    ticket_text = db.get_ticket(ref)["body"] if ref and db.get_ticket(ref) else ""
    plan = agent_mod.plan(
        instruction,
        user.get("role", "user"),
        ticket_text,
        auto_approve=bool(payload.get("auto_approve")),
    )
    if plan.tool == "denied":
        raise HTTPException(403, {"blocked": plan.args.get("wanted"), "audit": plan.audit})
    if plan.needs_approval:
        _PENDING_COUNTER["n"] += 1
        pid = f"appr-{_PENDING_COUNTER['n']}"
        _APPROVALS[pid] = {"plan": plan.tool, "args": plan.args, "approved": False}
        return {
            "status": "needs_approval",
            "approval_id": pid,
            "tool": plan.tool,
            "audit": plan.audit,
        }
    result = _execute(plan.tool, plan.args)
    return {
        "status": "executed",
        "tool": plan.tool,
        "result": result,
        "injected": plan.injected,
        "audit": plan.audit,
    }


@app.post("/api/agent/approve")
def approve(payload: dict):
    pid = payload.get("approval_id", "")
    rec = _APPROVALS.get(pid)
    if not rec:
        raise HTTPException(404, "no such approval")
    rec["approved"] = True
    result = _execute(rec["plan"], rec["args"])
    return {"status": "executed", "tool": rec["plan"], "result": result}


def _execute(tool: str, args: dict):
    if tool == "search_tickets":
        return [dict(r) for r in db.get_conn().execute("SELECT id,title FROM tickets").fetchall()]
    if tool == "summarize_ticket":
        t = db.get_ticket(args.get("id", 0))
        return {"summary": (t["body"][:40] if t else "not found")}
    if tool == "delete_ticket":
        db.get_conn().execute("DELETE FROM tickets WHERE id = ?", (args.get("id", 0),))
        db.get_conn().commit()
        return {"deleted": args.get("id")}
    if tool == "export_users":
        return [dict(r) for r in db.get_conn().execute("SELECT id,username,role FROM users")]
    return {"noop": tool}
