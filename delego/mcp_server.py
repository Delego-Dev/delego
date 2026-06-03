"""MCP facade — how an agent (Claude Code, Codex, etc.) talks to the firewall.

The agent never executes web actions directly. It *proposes* them here; the
firewall decides; allowed actions are carried out via the configured broker.
Sensitive actions come back as ``needs_approval`` with an approval id that a
human releases out-of-band (``delego approve <id>``), after which the agent
calls ``delego_resolve_action`` to complete it.

v0.1 uses the default :class:`NullBroker` (no real requests, no credentials).
Point it at a real credential broker to act on live services.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from .config import Paths, build_firewall
from .models import ProposedAction

mcp = FastMCP("delego_mcp")

_STRICT = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")


class ProposeInput(BaseModel):
    """Input for proposing an action to the firewall."""

    model_config = _STRICT

    instruction: str = Field(
        ...,
        description="The original human instruction that this action serves "
        "(e.g. 'pay my electricity bill'). Recorded and hashed for audit.",
        min_length=1,
    )
    method: str = Field(..., description="HTTP method, e.g. 'GET' or 'POST'", min_length=1)
    url: str = Field(..., description="Full target URL, e.g. 'https://api.examplebank.in/transfer'")
    params: dict = Field(
        default_factory=dict,
        description="Decision-relevant fields of the request "
        "(e.g. {'amount': 2400, 'currency': 'INR', 'beneficiary_type': 'domestic'}).",
    )


class ResolveInput(BaseModel):
    """Input for completing a previously approved action."""

    model_config = _STRICT

    approval_id: str = Field(..., description="The approval id returned by delego_propose_action")
    instruction: str = Field(..., description="Same instruction as the original proposal", min_length=1)
    method: str = Field(..., description="Same HTTP method as the original proposal", min_length=1)
    url: str = Field(..., description="Same URL as the original proposal")
    params: dict = Field(
        default_factory=dict, description="Same params as the original proposal (must match exactly)"
    )


class AuditTailInput(BaseModel):
    model_config = _STRICT
    lines: int = Field(default=20, description="Number of recent receipts to return", ge=1, le=200)


def _firewall():
    return build_firewall(Paths.resolve())


def _decision_json(decision) -> str:
    d = asdict(decision)
    d["result"] = decision.result  # keep nested dict as-is
    return json.dumps(d, indent=2)


@mcp.tool(
    name="delego_propose_action",
    annotations={
        "title": "Propose an action for authorisation",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def delego_propose_action(params: ProposeInput) -> str:
    """Submit an action for the firewall to authorise before it touches a service.

    The firewall evaluates the action against the deterministic policy and
    returns one of three outcomes:
      - ``allow``: the action was authorised and executed via the broker.
      - ``deny``: the action was refused (see ``reasons``).
      - ``needs_approval``: a human must approve first; an ``approval_id`` is
        returned. Once a human approves, call ``delego_resolve_action`` with the
        identical action to complete it.

    Returns:
        str: JSON with fields ``outcome``, ``rule``, ``reasons`` (list),
        ``intent_hash``, ``action_fingerprint``, ``approval_id`` (or null),
        ``executed`` (bool), and ``result`` (broker result or null).
    """
    action = ProposedAction(
        instruction=params.instruction, method=params.method, url=params.url, params=params.params
    )
    return _decision_json(_firewall().propose(action))


@mcp.tool(
    name="delego_resolve_action",
    annotations={
        "title": "Complete an approved action",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def delego_resolve_action(params: ResolveInput) -> str:
    """Complete an action that previously returned ``needs_approval``.

    The action you pass must be identical to the one that was proposed: its
    fingerprint must match the one the approval was issued for. A mismatch is
    denied as a possible substituted action.

    Returns:
        str: JSON with the same shape as ``delego_propose_action``. Outcome is
        ``allow`` (human approved, action executed), ``deny`` (human denied, or
        fingerprint mismatch), or ``needs_approval`` (still pending).
    """
    action = ProposedAction(
        instruction=params.instruction, method=params.method, url=params.url, params=params.params
    )
    return _decision_json(_firewall().resolve(params.approval_id, action))


@mcp.tool(
    name="delego_audit_tail",
    annotations={
        "title": "Read recent audit receipts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def delego_audit_tail(params: AuditTailInput) -> str:
    """Return the most recent audit receipts as JSON.

    Returns:
        str: JSON list of receipts, each with ``seq``, ``ts``, ``phase``,
        ``outcome``, ``rule``, ``reasons``, ``intent_hash``,
        ``action_fingerprint``, ``action_summary``, ``approval_id``, and the
        chain fields ``prev_hash``/``entry_hash``/``signature``.
    """
    return json.dumps(_firewall().audit.tail(params.lines), indent=2)


@mcp.tool(
    name="delego_show_policy",
    annotations={
        "title": "Show the active policy",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def delego_show_policy() -> str:
    """Return a summary of the active policy (version, default, rules, forbidden).

    Returns:
        str: JSON with ``version``, ``default``, ``forbidden`` (list of
        {name, match}) and ``rules`` (list of {name, decision, match,
        constraints}).
    """
    p = _firewall().policy
    out = {
        "version": p.version,
        "default": p.default,
        "forbidden": [{"name": r.name, "match": r.match} for r in p.forbidden],
        "rules": [
            {"name": r.name, "decision": r.decision, "match": r.match, "constraints": r.constraints}
            for r in p.rules
        ],
    }
    return json.dumps(out, indent=2)


def main() -> None:
    mcp.run()  # stdio transport for local use


if __name__ == "__main__":
    main()
