"""MCP facade — how an agent (Claude Code, Codex, etc.) talks to the firewall.

The agent never executes web actions directly. It *proposes* them here; the
firewall decides; allowed actions are carried out via the configured broker.
Sensitive actions come back as ``needs_approval`` with an approval id that a
human releases out-of-band (``delego approve <id>``), after which the agent
calls ``delego_resolve_action`` to complete it.

**Trust boundary.** Approving and denying are deliberately NOT exposed over
MCP: the agent proposing an action must never be able to approve it. The human
decision happens in a channel the agent does not control (the CLI, or an
approval surface built on the queue). This server offers the agent a read-only
view of its parked approvals (``delego_pending``) — nothing more.

By default the firewall uses :class:`NullBroker` (no real requests, no credentials).
Point it at a real credential broker to act on live services.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from .brokers import BrokerRefusal
from .config import Paths, build_firewall
from .models import OUTCOME_DENY, ProposedAction

mcp = FastMCP("delego_mcp")

_STRICT = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")


class ProposeInput(BaseModel):
    """Input for proposing an action to the firewall."""

    model_config = _STRICT

    instruction: str = Field(
        ...,
        description="The original human instruction that this action serves "
        "(e.g. 'place a small order'). Recorded and hashed for audit.",
        min_length=1,
    )
    method: str = Field(..., description="HTTP method, e.g. 'GET' or 'POST'", min_length=1)
    url: str = Field(..., description="Full target URL, e.g. 'https://api.example.com/orders'")
    params: dict = Field(
        default_factory=dict,
        description="Decision-relevant fields of the request "
        "(e.g. {'amount': 2400, 'currency': 'USD', 'destination': 'internal'}).",
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


def _decision_dict(decision) -> dict[str, Any]:
    d = asdict(decision)
    d["result"] = decision.result  # keep nested dict as-is
    return d


def _setup_required(e: Exception) -> dict[str, Any]:
    """The home isn't initialised (no policy / signing keys yet).

    Returned as a structured payload — not raised — so an agent can relay the
    one-time setup step to its human instead of surfacing a stack trace.
    Initialisation stays deliberate: a security tool should not silently
    generate its own signing keys on first contact.
    """
    return {
        "error": "setup_required",
        "detail": str(e),
        "fix": "Run `delego init` (or `delego init --home <dir>`, or set "
        "DELEGO_HOME) to install a starter policy and generate signing keys, "
        "then retry.",
    }


def _broker_refusal(action: ProposedAction, e: BrokerRefusal) -> dict[str, Any]:
    """A fail-closed broker refusal, shaped like a decision so agents handle it
    on the same code path as any other deny. The refusal is already recorded as
    an execution/deny receipt by the engine."""
    return {
        "outcome": OUTCOME_DENY,
        "rule": None,
        "reasons": [str(e)],
        "intent_hash": action.intent_hash,
        "action_fingerprint": action.fingerprint,
        "approval_id": None,
        "executed": False,
        "result": None,
        "note": "broker refused (fail-closed); the refusal is recorded in the audit ledger",
    }


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
async def delego_propose_action(params: ProposeInput) -> dict[str, Any]:
    """Submit an action for the firewall to authorise before it touches a service.

    The firewall evaluates the action against the deterministic policy and
    returns one of three outcomes:
      - ``allow``: the action was authorised and executed via the broker.
      - ``deny``: the action was refused (see ``reasons``).
      - ``needs_approval``: a human must approve first; an ``approval_id`` is
        returned. The human decides out-of-band (``delego approve <id>``) —
        approval is not available over MCP. Once approved, call
        ``delego_resolve_action`` with the identical action to complete it.

    Returns:
        dict with fields ``outcome``, ``rule``, ``reasons`` (list),
        ``intent_hash``, ``action_fingerprint``, ``approval_id`` (or null),
        ``executed`` (bool), and ``result`` (broker result or null) — or
        ``{"error": "setup_required", ...}`` if the delego home isn't
        initialised yet.
    """
    action = ProposedAction(
        instruction=params.instruction, method=params.method, url=params.url, params=params.params
    )
    try:
        return _decision_dict(_firewall().propose(action))
    except FileNotFoundError as e:
        return _setup_required(e)
    except BrokerRefusal as e:
        return _broker_refusal(action, e)


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
async def delego_resolve_action(params: ResolveInput) -> dict[str, Any]:
    """Complete an action that previously returned ``needs_approval``.

    The action you pass must be identical to the one that was proposed: its
    fingerprint must match the one the approval was issued for. A mismatch is
    denied as a possible substituted action (the deny reason names the action
    the approval was actually issued for, so you can correct and re-propose).

    Returns:
        dict with the same shape as ``delego_propose_action``. Outcome is
        ``allow`` (human approved, action executed), ``deny`` (human denied, or
        fingerprint mismatch), or ``needs_approval`` (still pending).
    """
    action = ProposedAction(
        instruction=params.instruction, method=params.method, url=params.url, params=params.params
    )
    try:
        return _decision_dict(_firewall().resolve(params.approval_id, action))
    except FileNotFoundError as e:
        return _setup_required(e)
    except BrokerRefusal as e:
        return _broker_refusal(action, e)


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
async def delego_audit_tail(params: AuditTailInput) -> list[dict[str, Any]] | dict[str, Any]:
    """Return the most recent audit receipts.

    Returns:
        list of receipts, each with ``seq``, ``ts``, ``phase``, ``outcome``,
        ``rule``, ``reasons``, ``intent_hash``, ``action_fingerprint``,
        ``action_summary``, ``approval_id``, and the chain fields
        ``prev_hash``/``entry_hash``/``signature`` — or a ``setup_required``
        payload if the delego home isn't initialised yet.
    """
    try:
        return _firewall().audit.tail(params.lines)
    except FileNotFoundError as e:
        return _setup_required(e)


@mcp.tool(
    name="delego_pending",
    annotations={
        "title": "List actions awaiting human approval",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def delego_pending() -> list[dict[str, Any]] | dict[str, Any]:
    """List parked actions still awaiting a human decision.

    Read-only. Approving or denying is deliberately not available over MCP —
    the agent that proposed an action must never be able to approve it; a
    human decides out-of-band (``delego approve <id>`` / ``delego deny <id>``).
    Use this to check what is still parked; to learn an approval's outcome,
    call ``delego_resolve_action`` with the identical action.

    Returns:
        list of pending approvals, each with ``id``, ``summary``,
        ``instruction``, ``rule``, ``action_fingerprint``, and ``created_at``
        — or a ``setup_required`` payload if the home isn't initialised yet.
    """
    try:
        pending = _firewall().approvals.pending()
    except FileNotFoundError as e:
        return _setup_required(e)
    return [
        {
            "id": r["id"],
            "summary": r.get("summary"),
            "instruction": r.get("instruction"),
            "rule": r.get("rule"),
            "action_fingerprint": r.get("action_fingerprint"),
            "created_at": r.get("created_at"),
        }
        for r in pending
    ]


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
async def delego_show_policy() -> dict[str, Any]:
    """Return a summary of the active policy (version, default, rules, forbidden).

    Returns:
        dict with ``version``, ``default``, ``forbidden`` (list of
        {name, match}) and ``rules`` (list of {name, decision, match,
        constraints}) — or a ``setup_required`` payload if the delego home
        isn't initialised yet.
    """
    try:
        p = _firewall().policy
    except FileNotFoundError as e:
        return _setup_required(e)
    return {
        "version": p.version,
        "default": p.default,
        "forbidden": [{"name": r.name, "match": r.match} for r in p.forbidden],
        "rules": [
            {"name": r.name, "decision": r.decision, "match": r.match, "constraints": r.constraints}
            for r in p.rules
        ],
    }


def main() -> None:
    mcp.run()  # stdio transport for local use


if __name__ == "__main__":
    main()
