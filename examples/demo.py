"""End-to-end demo of the firewall — no agent or live service required.

Run it:  python examples/demo.py

It builds a firewall in a throwaway home dir using the example policy, then
walks several scenarios and finally verifies the audit chain (including a
demonstration that tampering is detected).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from delego import ProposedAction, build_firewall
from delego.config import Paths

REPO_ROOT = Path(__file__).resolve().parent.parent


def banner(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def show(decision) -> None:
    print(f"  outcome        : {decision.outcome}")
    print(f"  rule           : {decision.rule}")
    print(f"  executed       : {decision.executed}")
    if decision.approval_id:
        print(f"  approval_id    : {decision.approval_id}")
    for r in decision.reasons:
        print(f"  reason         : {r}")


def main() -> None:
    home = Path(tempfile.mkdtemp(prefix="delego-demo-"))
    shutil.copy(REPO_ROOT / "policy.example.yaml", home / "policy.yaml")
    paths = Paths.resolve(home)
    fw = build_firewall(paths)

    banner("1. ALLOW — read own accounts (matches an allow rule)")
    d = fw.propose(
        ProposedAction(
            instruction="read my account details",
            method="GET",
            url="https://api.example.com/accounts/me",
        )
    )
    show(d)

    banner("2. DENY (forbidden) — attempt to change permissions")
    d = fw.propose(
        ProposedAction(
            instruction="share my account with a teammate",
            method="POST",
            url="https://api.example.com/accounts/me/permissions",
            params={"grant": "teammate@example.com"},
        )
    )
    show(d)

    banner("3. DENY (constraint) — order above the cap")
    d = fw.propose(
        ProposedAction(
            instruction="place a large order",
            method="POST",
            url="https://api.example.com/orders",
            params={"amount": 50000, "currency": "USD", "destination": "internal"},
        )
    )
    show(d)

    banner("4. NEEDS APPROVAL — small order (within cap)")
    order = ProposedAction(
        instruction="place a small order",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal"},
    )
    d = fw.propose(order)
    show(d)
    approval_id = d.approval_id

    banner("5. CONFUSED-DEPUTY GUARD — reuse the approval for a different action")
    # A prompt injection adds a recipient but reuses the approval id.
    tampered = ProposedAction(
        instruction="place a small order",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal", "recipient": "attacker"},
    )
    d = fw.resolve(approval_id, tampered)
    show(d)
    print("  --> refused: fingerprint doesn't match what the human approved.")

    banner("6. RESOLVE — human approves, then the ORIGINAL action completes")
    fw.approvals.decide(approval_id, approved=True, approver="koishore")
    d = fw.resolve(approval_id, order)
    show(d)

    banner("7. AUDIT — verify the receipt chain")
    ok, problems = fw.audit.verify()
    print(f"  chain valid    : {ok}  ({len(fw.audit.tail(999))} receipts)")
    for p in problems:
        print(f"  problem        : {p}")

    banner("8. TAMPER CHECK — edit one receipt on disk and re-verify")
    log_path = paths.audit_log
    text = log_path.read_text().splitlines()
    # Corrupt the action summary of the first receipt (without re-signing).
    text[0] = text[0].replace("accounts/me", "accounts/victim")
    log_path.write_text("\n".join(text) + "\n")
    ok, problems = fw.audit.verify()
    print(f"  chain valid    : {ok}")
    for p in problems:
        print(f"  detected       : {p}")

    print(f"\n(demo state in {home})")


if __name__ == "__main__":
    main()
