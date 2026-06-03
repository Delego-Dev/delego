"""The eight demo scenarios, encoded as regression tests.

``examples/demo.py`` is the de facto spec for delego's behaviour. Each test
below is one of its eight steps, with the same actions and the same expected
outcomes, so a regression in any core behaviour (allow / forbidden-deny /
cap-deny / needs-approval / the confused-deputy guard / resolve-after-approval /
a valid chain / tamper detection) fails the suite.

Actions are written out inline (full URLs and params) rather than hidden behind
helpers, deliberately: these tests double as readable documentation of what the
firewall does, the same way the demo does.
"""

from __future__ import annotations

from delego import (
    OUTCOME_ALLOW,
    OUTCOME_APPROVAL,
    OUTCOME_DENY,
    ProposedAction,
)
from delego.audit import GENESIS


def _canonical_session(fw) -> str:
    """Replay the demo's scenarios 1–6 against ``fw`` (6 receipts).

    Returns the approval id from the small-transfer step. Used by the
    chain-validity and tamper tests, which need a realistic multi-action ledger.
    """
    fw.propose(
        ProposedAction(
            instruction="check my balance",
            method="GET",
            url="https://api.examplebank.in/accounts/me",
        )
    )
    fw.propose(
        ProposedAction(
            instruction="share my statements with my accountant",
            method="POST",
            url="https://api.examplebank.in/accounts/me/permissions",
            params={"grant": "accountant@example.com"},
        )
    )
    fw.propose(
        ProposedAction(
            instruction="pay the contractor",
            method="POST",
            url="https://api.examplebank.in/transfer",
            params={"amount": 50000, "currency": "INR", "beneficiary_type": "domestic"},
        )
    )
    transfer = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic"},
    )
    d = fw.propose(transfer)
    tampered = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic", "to": "attacker"},
    )
    fw.resolve(d.approval_id, tampered)
    fw.approvals.decide(d.approval_id, approved=True, approver="koishore")
    fw.resolve(d.approval_id, transfer)
    return d.approval_id


# --------------------------------------------------------------------------- #
# 1. ALLOW — read own accounts (matches an allow rule)
# --------------------------------------------------------------------------- #
def test_scenario_1_allow_read_accounts(firewall):
    d = firewall.propose(
        ProposedAction(
            instruction="check my balance",
            method="GET",
            url="https://api.examplebank.in/accounts/me",
        )
    )
    assert d.outcome == OUTCOME_ALLOW
    assert d.allowed is True
    assert d.rule == "read-accounts"
    assert d.executed is True
    # Executed through the (stub) broker, which holds no credentials.
    assert d.result["status"] == "simulated"
    # Exactly one receipt — the execution — and the chain is intact.
    receipts = firewall.audit.tail(999)
    assert len(receipts) == 1
    assert receipts[0]["phase"] == "execution"
    assert receipts[0]["outcome"] == "allow"
    ok, problems = firewall.audit.verify()
    assert ok is True
    assert problems == []


# --------------------------------------------------------------------------- #
# 2. DENY (forbidden) — attempt to change permissions
# --------------------------------------------------------------------------- #
def test_scenario_2_forbidden_deny(firewall):
    d = firewall.propose(
        ProposedAction(
            instruction="share my statements with my accountant",
            method="POST",
            url="https://api.examplebank.in/accounts/me/permissions",
            params={"grant": "accountant@example.com"},
        )
    )
    assert d.outcome == OUTCOME_DENY
    assert d.allowed is False
    assert d.rule == "no-access-control-changes"
    assert d.executed is False
    assert any(r.startswith("forbidden:") for r in d.reasons)


# --------------------------------------------------------------------------- #
# 3. DENY (constraint) — transfer above the cap (fail-closed)
# --------------------------------------------------------------------------- #
def test_scenario_3_constraint_deny_over_cap(firewall):
    d = firewall.propose(
        ProposedAction(
            instruction="pay the contractor",
            method="POST",
            url="https://api.examplebank.in/transfer",
            params={"amount": 50000, "currency": "INR", "beneficiary_type": "domestic"},
        )
    )
    # The rule matches (small-domestic-transfer) but its amount cap fails, so a
    # matched-rule-with-failed-constraint becomes a deny — never a silent allow.
    assert d.outcome == OUTCOME_DENY
    assert d.rule == "small-domestic-transfer"
    assert d.executed is False
    assert any("exceeds max" in r for r in d.reasons)


# --------------------------------------------------------------------------- #
# 4. NEEDS APPROVAL — small domestic transfer (within cap)
# --------------------------------------------------------------------------- #
def test_scenario_4_needs_approval(firewall):
    transfer = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic"},
    )
    d = firewall.propose(transfer)
    assert d.outcome == OUTCOME_APPROVAL
    assert d.rule == "small-domestic-transfer"
    assert d.executed is False
    assert d.approval_id is not None
    # The action is parked, pending, and bound to its exact fingerprint.
    rec = firewall.approvals.get(d.approval_id)
    assert rec is not None
    assert rec["status"] == "pending"
    assert rec["action_fingerprint"] == transfer.fingerprint
    assert [p["id"] for p in firewall.approvals.pending()] == [d.approval_id]
    # A decision receipt was written for the parking.
    receipts = firewall.audit.tail(999)
    assert len(receipts) == 1
    assert receipts[0]["phase"] == "decision"
    assert receipts[0]["outcome"] == OUTCOME_APPROVAL
    assert receipts[0]["approval_id"] == d.approval_id


# --------------------------------------------------------------------------- #
# 5. CONFUSED-DEPUTY GUARD — reuse the approval for a different action
# --------------------------------------------------------------------------- #
def test_scenario_5_confused_deputy_guard(firewall):
    transfer = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic"},
    )
    d = firewall.propose(transfer)

    # A prompt injection adds a beneficiary but reuses the approval id.
    tampered = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic", "to": "attacker"},
    )
    assert tampered.fingerprint != transfer.fingerprint

    res = firewall.resolve(d.approval_id, tampered)
    assert res.outcome == OUTCOME_DENY
    assert res.rule is None
    assert res.executed is False
    assert any(("mismatch" in r) or ("substituted" in r) for r in res.reasons)

    # The approval is NOT consumed — it stays pending, so the substituted action
    # never rides the human's "yes".
    assert firewall.approvals.get(d.approval_id)["status"] == "pending"
    # The refusal is recorded as an execution/deny receipt.
    last = firewall.audit.tail(999)[-1]
    assert last["phase"] == "execution"
    assert last["outcome"] == OUTCOME_DENY


# --------------------------------------------------------------------------- #
# 6. RESOLVE — human approves, then the ORIGINAL action completes
# --------------------------------------------------------------------------- #
def test_scenario_6_resolve_after_approval(firewall):
    transfer = ProposedAction(
        instruction="pay my electricity bill",
        method="POST",
        url="https://api.examplebank.in/transfer",
        params={"amount": 2400, "currency": "INR", "beneficiary_type": "domestic"},
    )
    d = firewall.propose(transfer)
    firewall.approvals.decide(d.approval_id, approved=True, approver="koishore")

    res = firewall.resolve(d.approval_id, transfer)
    assert res.outcome == OUTCOME_ALLOW
    assert res.executed is True
    assert res.result["status"] == "simulated"
    assert any("human approved" in r for r in res.reasons)


# --------------------------------------------------------------------------- #
# 7. AUDIT — the receipt chain verifies after a full session
# --------------------------------------------------------------------------- #
def test_scenario_7_chain_valid(firewall):
    _canonical_session(firewall)

    ok, problems = firewall.audit.verify()
    assert ok is True
    assert problems == []

    receipts = firewall.audit.tail(999)
    assert len(receipts) == 6
    # Sequence numbers are contiguous from zero...
    assert [r["seq"] for r in receipts] == list(range(6))
    # ...and each receipt links to the previous one's hash (genesis first).
    assert receipts[0]["prev_hash"] == GENESIS
    for prev, cur in zip(receipts, receipts[1:]):
        assert cur["prev_hash"] == prev["entry_hash"]


# --------------------------------------------------------------------------- #
# 8. TAMPER CHECK — editing one receipt on disk breaks verification
# --------------------------------------------------------------------------- #
def test_scenario_8_tamper_detected(firewall):
    _canonical_session(firewall)
    assert firewall.audit.verify()[0] is True  # valid before tampering

    # Corrupt the action summary of the first receipt without re-signing it.
    log_path = firewall.audit.path
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("accounts/me", "accounts/victim")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, problems = firewall.audit.verify()
    assert ok is False
    assert any("content hash mismatch" in p for p in problems)
    assert any("seq 0" in p for p in problems)
