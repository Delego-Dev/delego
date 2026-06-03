"""Concurrent-writer safety for the file-backed ledger and approval store.

The audit append and the approval decide/consume paths are read-modify-write;
without the file lock added in 0.2.1, two writers racing that window fork the
hash chain or interleave a torn record. These tests drive that contention with
threads (each ``file_lock`` opens its own descriptor, so the exclusive lock
serialises them) and assert integrity holds.

They guard write *integrity*, not rate-limit exactness under concurrency — that
count→execute→append window is closed only by the single-writer daemon.
"""

from __future__ import annotations

import threading

H = "0" * 64  # a stand-in 64-hex hash for fields the tests don't vary


def _run(target, n):
    threads = [threading.Thread(target=target, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# --------------------------------------------------------------------------- #
# the hash chain stays valid and contiguous under concurrent appends
# --------------------------------------------------------------------------- #
def test_concurrent_appends_keep_chain_valid(firewall):
    n = 25

    def append(i):
        firewall.audit.append(
            phase="decision",
            outcome="deny",
            rule=None,
            reasons=[f"r{i}"],
            intent_hash=H,
            action_fingerprint=H,
            action_summary=f"action-{i}",
            approval_id=None,
        )

    _run(append, n)

    receipts = firewall.audit.tail(10_000)
    assert len(receipts) == n
    # No forked chain: seqs are exactly 0..n-1, and the signed chain verifies.
    assert sorted(r["seq"] for r in receipts) == list(range(n))
    ok, problems = firewall.audit.verify()
    assert ok, problems


# --------------------------------------------------------------------------- #
# concurrent approval creates all land intact (no torn / lost records)
# --------------------------------------------------------------------------- #
def test_concurrent_approval_creates_are_intact(firewall):
    n = 25
    ids: list[str] = []
    guard = threading.Lock()

    def create(i):
        aid = firewall.approvals.create(action_fingerprint=H, intent_hash=H, summary=f"s{i}")
        with guard:
            ids.append(aid)

    _run(create, n)

    records = firewall.approvals._read()  # parses every line; a torn line would raise
    assert len(records) == n
    assert set(ids) == set(records) and len(ids) == n


# --------------------------------------------------------------------------- #
# concurrent decisions on one approval converge to a single terminal status
# --------------------------------------------------------------------------- #
def test_concurrent_decide_is_single_winner(firewall):
    aid = firewall.approvals.create(action_fingerprint=H, intent_hash=H, summary="s")
    seen: list[str] = []
    guard = threading.Lock()

    def decide(i):
        rec = firewall.approvals.decide(aid, approved=(i % 2 == 0), approver=f"t{i}")
        with guard:
            seen.append(rec["status"])

    _run(decide, 20)

    final = firewall.approvals.get(aid)["status"]
    assert final in ("approved", "denied")
    # First decision wins; every later decide is idempotent and returns that same
    # terminal status — the lock prevents a second decision from flipping it.
    assert all(s == final for s in seen)
