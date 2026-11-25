"""A mock "AI agent" that maps a natural-language instruction to a tool call.

There is no real model: a tiny rule-based planner stands in for one so the lab is
deterministic and needs no API keys. The security-relevant parts are faithful:

* a tool allow-list scoped per role,
* a human-approval gate for destructive tools,
* a planner that reads the user instruction *and* ticket content (the injection sink).

VULN build:
* the planner honours instructions found inside ticket text (prompt injection),
* it will call tools outside the caller's allow-list (tool abuse / boundary break),
* the approval gate can be bypassed with an "auto_approve" flag in the instruction.

FIXED build: ticket content is treated as data, the allow-list is enforced, and
destructive tools always require an out-of-band approval token.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import FIXED

# Tools and which roles may invoke them.
TOOL_SCOPE = {
    "search_tickets": {"user", "admin"},
    "summarize_ticket": {"user", "admin"},
    "delete_ticket": {"admin"},  # destructive, admin only
    "export_users": {"admin"},  # sensitive, admin only
}
DESTRUCTIVE = {"delete_ticket"}


@dataclass
class Plan:
    tool: str
    args: dict
    needs_approval: bool
    reason: str = ""
    injected: bool = False
    audit: list[str] = field(default_factory=list)


_INJECTION = re.compile(r"(ignore .*instructions|system:|tool:\s*(\w+)|delete ticket (\d+))", re.I)


def plan(instruction: str, role: str, ticket_text: str = "", auto_approve: bool = False) -> Plan:
    """Decide which tool to call. ``ticket_text`` is untrusted content from the store."""
    audit: list[str] = []
    injected = False

    if not FIXED and ticket_text:
        # VULN: ticket content is concatenated into the planner input, so text stored
        # by another user can steer the agent (indirect prompt injection).
        match = _INJECTION.search(ticket_text)
        if match:
            injected = True
            audit.append(f"followed instruction embedded in ticket: {match.group(0)!r}")
            if match.group(3):
                return _finish(
                    "delete_ticket",
                    {"id": int(match.group(3))},
                    role,
                    auto_approve,
                    injected,
                    audit,
                )
            if match.group(2):
                return _finish(match.group(2), {}, role, auto_approve, injected, audit)

    text = instruction.lower()
    if "delete" in text:
        m = re.search(r"delete ticket (\d+)", text)
        return _finish(
            "delete_ticket",
            {"id": int(m.group(1)) if m else 0},
            role,
            auto_approve,
            injected,
            audit,
        )
    if "export" in text and "user" in text:
        return _finish("export_users", {}, role, auto_approve, injected, audit)
    if "summar" in text:
        m = re.search(r"ticket (\d+)", text)
        return _finish(
            "summarize_ticket",
            {"id": int(m.group(1)) if m else 0},
            role,
            auto_approve,
            injected,
            audit,
        )
    return _finish("search_tickets", {"q": instruction}, role, auto_approve, injected, audit)


def _finish(tool, args, role, auto_approve, injected, audit) -> Plan:
    allowed = role in TOOL_SCOPE.get(tool, set())
    if not allowed:
        if FIXED:
            audit.append(f"blocked: role {role!r} may not call {tool!r}")
            return Plan("denied", {"wanted": tool}, False, "out of scope", injected, audit)
        # VULN: boundary not enforced — the out-of-scope tool runs anyway.
        audit.append(f"VULN: role {role!r} allowed to call out-of-scope {tool!r}")

    needs_approval = tool in DESTRUCTIVE
    if needs_approval and auto_approve and not FIXED:
        # VULN: a self-asserted flag bypasses the human gate.
        needs_approval = False
        audit.append("VULN: approval auto-bypassed via auto_approve flag")
    return Plan(tool, args, needs_approval, "", injected, audit)
