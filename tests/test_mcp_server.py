"""MCP facade: structured output, fail-closed shapes, and the trust boundary.

The 0.3.1 UX contract: every tool returns structured data (dicts/lists, not
JSON-encoded strings), an uninitialised home comes back as a ``setup_required``
payload rather than a raised exception, a broker refusal is shaped like a deny,
and the only approval surface exposed to the agent is read-only.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp")

from delego import build_firewall, mcp_server  # noqa: E402
from delego.config import Paths  # noqa: E402
from delego.mcp_server import (  # noqa: E402
    AuditTailInput,
    ProposeInput,
    ResolveInput,
    delego_audit_tail,
    delego_pending,
    delego_propose_action,
    delego_resolve_action,
    delego_show_policy,
)


@pytest.fixture
def mcp_home(firewall, monkeypatch):
    """Point the MCP server at an initialised, isolated home."""
    home = firewall.audit.path.parent
    monkeypatch.setattr(mcp_server, "_firewall", lambda: build_firewall(Paths.resolve(home)))
    return firewall


def _run(coro):
    return asyncio.run(coro)


def _tool_names() -> list[str]:
    return [t.name for t in _run(mcp_server.mcp.list_tools())]


def test_propose_returns_structured_dict(mcp_home):
    out = _run(
        delego_propose_action(
            ProposeInput(
                instruction="read my account details",
                method="GET",
                url="https://api.example.com/accounts/me",
            )
        )
    )
    assert isinstance(out, dict)  # not a JSON-encoded string
    assert out["outcome"] == "allow"
    assert out["executed"] is True
    assert out["result"]["status"] == "simulated"


def test_uninitialised_home_returns_setup_required(tmp_path, monkeypatch):
    empty = tmp_path / "empty-home"
    empty.mkdir()
    monkeypatch.setattr(mcp_server, "_firewall", lambda: build_firewall(Paths.resolve(empty)))
    out = _run(delego_show_policy())
    assert out["error"] == "setup_required"
    assert "delego init" in out["fix"]


def test_broker_refusal_is_deny_shaped_not_raised(mcp_home):
    out = _run(
        delego_propose_action(
            ProposeInput(
                instruction="read my account details",
                method="GET",
                url="https://api.example.com/accounts/me#smuggled",
            )
        )
    )
    assert out["outcome"] == "deny"
    assert out["executed"] is False
    assert any("fragment" in r for r in out["reasons"])
    # ...and the refusal left a receipt (audit completeness).
    last = _run(delego_audit_tail(AuditTailInput(lines=1)))[-1]
    assert last["outcome"] == "deny" and last["phase"] == "execution"


def test_pending_is_read_only_view_of_parked_actions(mcp_home):
    parked = _run(
        delego_propose_action(
            ProposeInput(
                instruction="place a small order",
                method="POST",
                url="https://api.example.com/orders",
                params={"amount": 2400, "currency": "USD", "destination": "internal"},
            )
        )
    )
    assert parked["outcome"] == "needs_approval"

    pending = _run(delego_pending())
    assert [p["id"] for p in pending] == [parked["approval_id"]]
    assert pending[0]["instruction"] == "place a small order"
    # The view is read-only: no approve/deny tool exists on the MCP surface.
    assert not any("approve" in name or "deny" in name for name in _tool_names())


def test_resolve_mismatch_names_the_approved_action(mcp_home):
    parked = _run(
        delego_propose_action(
            ProposeInput(
                instruction="place a small order",
                method="POST",
                url="https://api.example.com/orders",
                params={"amount": 2400, "currency": "USD", "destination": "internal"},
            )
        )
    )
    out = _run(
        delego_resolve_action(
            ResolveInput(
                approval_id=parked["approval_id"],
                instruction="place a small order",
                method="POST",
                url="https://api.example.com/orders?to=attacker",
                params={"amount": 2400, "currency": "USD", "destination": "internal"},
            )
        )
    )
    assert out["outcome"] == "deny"
    # The deny says what the approval WAS for, so the agent can self-correct.
    assert any("the approval was issued for: POST api.example.com/orders" in r for r in out["reasons"])
