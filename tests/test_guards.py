"""Invariant guards beyond the eight demo scenarios.

These are secondary to ``test_scenarios.py`` but they pin down the core security
properties at their edges: the ``resolve`` paths the demo doesn't walk, the
fail-closed rate limit, and the determinism of the fingerprint/intent hashes the
confused-deputy guard relies on.
"""

from __future__ import annotations

import json

from delego import (
    OUTCOME_ALLOW,
    OUTCOME_APPROVAL,
    OUTCOME_DENY,
    ProposedAction,
)


def _small_order() -> ProposedAction:
    return ProposedAction(
        instruction="place a small order",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal"},
    )


# --------------------------------------------------------------------------- #
# resolve() edge paths
# --------------------------------------------------------------------------- #
def test_resolve_unknown_approval_id_denies(firewall):
    res = firewall.resolve("apr_doesnotexist", _small_order())
    assert res.outcome == OUTCOME_DENY
    assert res.executed is False
    assert any("unknown approval" in r for r in res.reasons)
    # The probe leaves evidence: recorded as an execution/deny receipt (spec §7).
    last = firewall.audit.tail(1)[-1]
    assert last["phase"] == "execution" and last["outcome"] == OUTCOME_DENY
    assert any("unknown approval" in r for r in last["reasons"])


def test_resolve_while_pending_returns_needs_approval(firewall):
    order = _small_order()
    d = firewall.propose(order)
    # Fingerprint matches, but no human has decided yet: not executed.
    res = firewall.resolve(d.approval_id, order)
    assert res.outcome == OUTCOME_APPROVAL
    assert res.executed is False
    assert any("awaiting" in r for r in res.reasons)
    assert firewall.approvals.get(d.approval_id)["status"] == "pending"


def test_human_denied_then_resolve_denies(firewall):
    order = _small_order()
    d = firewall.propose(order)
    firewall.approvals.decide(d.approval_id, approved=False, approver="koishore")

    res = firewall.resolve(d.approval_id, order)
    assert res.outcome == OUTCOME_DENY
    assert res.executed is False
    assert any("denied" in r for r in res.reasons)
    last = firewall.audit.tail(999)[-1]
    assert last["phase"] == "execution"
    assert last["outcome"] == OUTCOME_DENY


# --------------------------------------------------------------------------- #
# approvals are single-use: one human "yes" releases the action exactly once
# --------------------------------------------------------------------------- #
def test_approval_is_single_use(firewall):
    order = _small_order()
    d = firewall.propose(order)
    firewall.approvals.decide(d.approval_id, approved=True, approver="koishore")

    first = firewall.resolve(d.approval_id, order)
    assert first.outcome == OUTCOME_ALLOW
    assert first.executed is True

    # Replaying the same approved id must NOT execute the action again.
    second = firewall.resolve(d.approval_id, order)
    assert second.outcome == OUTCOME_DENY
    assert second.executed is False
    assert any("already used" in r for r in second.reasons)

    # The approval is consumed, and exactly one allow receipt exists for it.
    assert firewall.approvals.get(d.approval_id)["status"] == "consumed"
    allows = [e for e in firewall.audit.tail(999) if e["outcome"] == OUTCOME_ALLOW]
    assert len(allows) == 1
    # The replay was recorded as an execution/deny.
    assert firewall.audit.tail(999)[-1]["outcome"] == OUTCOME_DENY


# --------------------------------------------------------------------------- #
# the approval is bound to the instruction too, not just the action fingerprint
# --------------------------------------------------------------------------- #
def test_resolve_with_different_instruction_denies(firewall):
    order = _small_order()
    d = firewall.propose(order)
    firewall.approvals.decide(d.approval_id, approved=True, approver="koishore")

    # Same action (identical fingerprint) but a different claimed instruction.
    restated = ProposedAction(
        instruction="send the deposit to my landlord",
        method=order.method,
        url=order.url,
        params=order.params,
    )
    assert restated.fingerprint == order.fingerprint  # the action is unchanged
    assert restated.intent_hash != order.intent_hash  # but the intent is not

    res = firewall.resolve(d.approval_id, restated)
    assert res.outcome == OUTCOME_DENY
    assert res.executed is False
    assert any("intent mismatch" in r for r in res.reasons)
    # Not consumed — the genuine instruction can still be resolved.
    assert firewall.approvals.get(d.approval_id)["status"] == "approved"


def test_resolve_with_substituted_query_denies(firewall):
    # Protocol 0.3: the query is folded into the fingerprint, so an approval
    # granted for one query cannot release the same path with another — the
    # exact confused-deputy gap the 0.2 preimage left open (spec §4.2, §7).
    order = _small_order()
    d = firewall.propose(order)
    firewall.approvals.decide(d.approval_id, approved=True, approver="koishore")

    redirected = ProposedAction(
        instruction=order.instruction,
        method=order.method,
        url=order.url + "?to=attacker",
        params=order.params,
    )
    assert redirected.fingerprint != order.fingerprint

    res = firewall.resolve(d.approval_id, redirected)
    assert res.outcome == OUTCOME_DENY
    assert res.executed is False
    assert any("action mismatch" in r for r in res.reasons)
    # The deny names the approved action so a drifted caller can self-correct.
    assert any("the approval was issued for: POST api.example.com/orders" in r for r in res.reasons)
    # Not consumed — the approved action itself can still be released.
    assert firewall.approvals.get(d.approval_id)["status"] == "approved"


# A single GET rule capped at 1 allow/hour — shared by the two rate-limit tests.
RATE_LIMITED_POLICY = """
version: 1
default: deny
rules:
  - name: read-accounts
    decision: allow
    match: { method: GET, host: api.example.com, path: /accounts/** }
    constraints:
      rate_limit: { max: 1, per: hour }
"""


# --------------------------------------------------------------------------- #
# a rate limit that cannot be evaluated must fail closed, never silently pass
# --------------------------------------------------------------------------- #
def test_rate_limit_without_audit_fails_closed(make_firewall):
    fw = make_firewall(RATE_LIMITED_POLICY)
    action = ProposedAction(
        instruction="read my account details",
        method="GET",
        url="https://api.example.com/accounts/me",
    )
    # Evaluate the policy with no audit log available to read the counter.
    outcome, rule, reasons = fw.policy.evaluate(action, audit=None)
    assert outcome == OUTCOME_DENY
    assert any("rate_limit" in r for r in reasons)


# --------------------------------------------------------------------------- #
# verify() reports tampering instead of crashing when a field is removed
# --------------------------------------------------------------------------- #
def test_verify_reports_removed_field_without_crashing(firewall):
    firewall.propose(
        ProposedAction(
            instruction="read my account details",
            method="GET",
            url="https://api.example.com/accounts/me",
        )
    )
    assert firewall.audit.verify()[0] is True

    # Delete a signed field from the first receipt (a cruder tamper than editing).
    path = firewall.audit.path
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    del rows[0]["intent_hash"]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    ok, problems = firewall.audit.verify()  # must not raise
    assert ok is False
    assert any("missing field" in p for p in problems)


# --------------------------------------------------------------------------- #
# rate_limit is fail-closed once the cap is reached
# --------------------------------------------------------------------------- #
def test_rate_limit_denies_after_cap(make_firewall):
    fw = make_firewall(RATE_LIMITED_POLICY)
    action = ProposedAction(
        instruction="read my account details",
        method="GET",
        url="https://api.example.com/accounts/me",
    )
    first = fw.propose(action)
    assert first.outcome == OUTCOME_ALLOW

    # The first allow is counted from the ledger; the second exceeds the cap.
    second = fw.propose(action)
    assert second.outcome == OUTCOME_DENY
    assert any("rate_limit" in r for r in second.reasons)


# --------------------------------------------------------------------------- #
# fingerprint / intent-hash determinism (what the confused-deputy guard needs)
# --------------------------------------------------------------------------- #
def test_fingerprint_is_deterministic_and_param_sensitive():
    a = _small_order()
    b = _small_order()
    # Identical actions hash identically...
    assert a.fingerprint == b.fingerprint
    assert a.intent_hash == b.intent_hash

    # ...adding a parameter (the substituted action) changes the fingerprint...
    c = ProposedAction(
        instruction="place a small order",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal", "recipient": "attacker"},
    )
    assert c.fingerprint != a.fingerprint
    # ...but intent binds to the instruction, which is unchanged.
    assert c.intent_hash == a.intent_hash


def test_fingerprint_normalises_method_host_and_param_order():
    a = _small_order()
    # Lowercase method, uppercase host, and shuffled param order must all
    # normalise to the same fingerprint (method.upper, host.lower, sorted JSON).
    normalised = ProposedAction(
        instruction="place a small order",
        method="post",
        url="https://API.EXAMPLE.COM/orders",
        params={"destination": "internal", "currency": "USD", "amount": 2400},
    )
    assert normalised.fingerprint == a.fingerprint


def test_intent_hash_ignores_surrounding_whitespace():
    spaced = ProposedAction(
        instruction="  place a small order  ",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal"},
    )
    assert spaced.intent_hash == _small_order().intent_hash


# --------------------------------------------------------------------------- #
# amount constraint is fail-closed against non-finite / negative / non-numeric
# --------------------------------------------------------------------------- #
def test_amount_rejects_non_finite_negative_and_bool(firewall):
    # `float('nan') > cap` is False, so a NaN amount used to *pass* the cap.
    for bad in ["nan", "inf", "-inf", -100, True, "not-a-number"]:
        d = firewall.propose(
            ProposedAction(
                instruction="place a small order",
                method="POST",
                url="https://api.example.com/orders",
                params={"amount": bad, "currency": "USD", "destination": "internal"},
            )
        )
        assert d.outcome == OUTCOME_DENY, f"amount={bad!r} should be denied, got {d.outcome}"
    # a normal value still parks for approval (the cap itself still works)
    ok = firewall.propose(
        ProposedAction(
            instruction="place a small order",
            method="POST",
            url="https://api.example.com/orders",
            params={"amount": 2400, "currency": "USD", "destination": "internal"},
        )
    )
    assert ok.outcome == OUTCOME_APPROVAL


# --------------------------------------------------------------------------- #
# verify(expected_head=...) catches tail-truncation that the chain alone can't
# --------------------------------------------------------------------------- #
def test_verify_expected_head_detects_truncation(firewall):
    h = "0" * 64
    for i in range(2):
        last = firewall.audit.append(
            phase="decision", outcome="deny", rule=None, reasons=[f"r{i}"],
            intent_hash=h, action_fingerprint=h, action_summary=f"a{i}", approval_id=None,
        )
    head = (last["seq"], last["entry_hash"])
    assert firewall.audit.verify(expected_head=head)[0] is True

    # drop the last receipt — a tail-truncated ledger is a valid prefix...
    lines = firewall.audit.path.read_text(encoding="utf-8").splitlines()
    firewall.audit.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert firewall.audit.verify()[0] is True  # ...so it still verifies on its own

    # ...but fails against the externally-anchored head.
    ok, problems = firewall.audit.verify(expected_head=head)
    assert ok is False
    assert any("truncated or rolled back" in p for p in problems)
