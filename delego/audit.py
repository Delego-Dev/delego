"""Tamper-evident audit log.

Every decision the firewall makes is written as a *receipt*. Receipts form a
hash chain (each carries the previous receipt's hash) and each is signed with a
local Ed25519 key. That gives two properties a regulator actually asks for:

* **Integrity** — editing or deleting any past receipt breaks the chain, and
  re-signing requires the private key.
* **Reconstructable authority path** — every receipt records the intent hash,
  the action fingerprint, the matched rule, and the outcome, so you can replay
  exactly *why* an action was allowed and *which instruction* authorised it.

This is the append-only ledger; ``verify()`` walks and checks the whole chain.

**Locking.** ``append`` takes the cross-process file lock for its read-modify-write
so concurrent writers can't fork the chain. ``transaction()`` exposes that same
lock to a caller that must keep a count→decide→append sequence atomic — the
rate-limit enforcement in ``engine.py`` uses it so concurrent ``propose`` calls
cannot collectively exceed a cap (each would otherwise count under-cap before any
appends its allow). The lock is **not** re-entrant, so the in-transaction
``append`` does not re-acquire it.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._locking import file_lock
from .util import canonical_json, now_iso, sha256_hex

# Fields that make up the signed payload, in a fixed set. ``entry_hash`` and
# ``signature`` are derived from these and excluded from the hashed payload.
_PAYLOAD_KEYS = (
    "seq",
    "ts",
    "phase",
    "outcome",
    "rule",
    "reasons",
    "intent_hash",
    "action_fingerprint",
    "action_summary",
    "approval_id",
    "prev_hash",
)

GENESIS = "GENESIS"


def ensure_keys(priv_path: Path, pub_path: Path) -> None:
    """Generate a local Ed25519 signing keypair if one doesn't exist."""
    priv_path = Path(priv_path)
    pub_path = Path(pub_path)
    if priv_path.exists():
        return
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


class _LockedAudit:
    """A view of an :class:`AuditLog` while its file lock is already held.

    Handed to the body of :meth:`AuditLog.transaction`. Its ``append`` and
    ``count_allows`` do **not** take the lock (the transaction holds it), so a
    count→decide→append sequence stays atomic across processes.
    """

    def __init__(self, log: "AuditLog") -> None:
        self._log = log

    def count_allows(self, rule: str, within_seconds: int) -> int:
        return self._log._count_allows(rule, within_seconds)

    def append(self, **payload) -> dict:
        return self._log._append_locked(**payload)


class AuditLog:
    def __init__(self, path, private_key_path, public_key_path):
        self.path = Path(path)
        self.priv_path = Path(private_key_path)
        self.pub_path = Path(public_key_path)
        self._priv: Optional[Ed25519PrivateKey] = None
        self._pub: Optional[Ed25519PublicKey] = None

    # -- keys ------------------------------------------------------------- #
    def _load_keys(self) -> None:
        if self._priv is None:
            self._priv = serialization.load_pem_private_key(
                self.priv_path.read_bytes(), password=None
            )
            self._pub = serialization.load_pem_public_key(self.pub_path.read_bytes())

    # -- read --------------------------------------------------------------#
    def _entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def _last(self) -> Optional[dict]:
        entries = self._entries()
        return entries[-1] if entries else None

    # -- write ------------------------------------------------------------ #
    def _append_locked(
        self,
        *,
        phase: str,
        outcome: str,
        rule: Optional[str],
        reasons: list[str],
        intent_hash: str,
        action_fingerprint: str,
        action_summary: str,
        approval_id: Optional[str] = None,
    ) -> dict:
        """The read-modify-write body of an append. **The file lock MUST already
        be held** (by :meth:`append` or :meth:`transaction`); this method does not
        take it, so it can run inside a larger atomic section without deadlocking
        on the non-re-entrant lock."""
        self._load_keys()
        last = self._last()
        seq = (last["seq"] + 1) if last else 0
        prev_hash = last["entry_hash"] if last else GENESIS

        payload = {
            "seq": seq,
            "ts": now_iso(),
            "phase": phase,
            "outcome": outcome,
            "rule": rule,
            "reasons": reasons,
            "intent_hash": intent_hash,
            "action_fingerprint": action_fingerprint,
            "action_summary": action_summary,
            "approval_id": approval_id,
            "prev_hash": prev_hash,
        }
        entry_hash = sha256_hex(canonical_json(payload))
        signature = self._priv.sign(entry_hash.encode("utf-8")).hex()
        entry = {**payload, "entry_hash": entry_hash, "signature": signature}

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def append(
        self,
        *,
        phase: str,
        outcome: str,
        rule: Optional[str],
        reasons: list[str],
        intent_hash: str,
        action_fingerprint: str,
        action_summary: str,
        approval_id: Optional[str] = None,
    ) -> dict:
        # Lock the whole read-modify-write: another writer must not slip a
        # receipt between our `_last()` and our append, or the chain forks.
        with file_lock(self.path):
            return self._append_locked(
                phase=phase,
                outcome=outcome,
                rule=rule,
                reasons=reasons,
                intent_hash=intent_hash,
                action_fingerprint=action_fingerprint,
                action_summary=action_summary,
                approval_id=approval_id,
            )

    @contextmanager
    def transaction(self) -> Iterator[_LockedAudit]:
        """Hold the ledger's file lock for the duration of the block.

        Use this when a *count then append* must be atomic — chiefly rate-limit
        enforcement, where two concurrent ``propose`` calls would each read
        ``used < max`` and then both append an allow, exceeding the cap. Within
        the block, use the yielded :class:`_LockedAudit` (its ``count_allows`` and
        ``append`` run lock-free under the held lock). Keep the block short: it
        serialises all ledger writers, and any work inside it (e.g. a broker call)
        holds the lock for that whole duration.
        """
        self._load_keys()
        with file_lock(self.path):
            yield _LockedAudit(self)

    # -- verify ----------------------------------------------------------- #
    def verify(
        self, expected_head: Optional[tuple[int, str]] = None
    ) -> tuple[bool, list[str]]:
        """Walk the chain: recompute hashes, check linkage, verify signatures.

        Tampering takes many forms — an edited field, a *removed* field, an
        unparseable line — so every step is defensive: a malformed receipt is
        reported as a problem, never allowed to crash the verification (a verifier
        that throws is a verifier an attacker can silence by corrupting one line).

        **Truncation caveat.** Hash-chaining catches edits, reordering, and
        deletions from the *middle*, but **not** truncation of the most recent
        receipts: a tail-truncated ledger is still an internally valid prefix and
        verifies clean on its own. Nor does any of this help against an attacker
        who holds the (local) signing key. To detect rollback you must anchor the
        head *outside* this file: persist the ``(seq, entry_hash)`` returned by
        ``append`` somewhere the attacker can't also rewrite, and pass it as
        ``expected_head`` here — verification then fails if the ledger's last
        receipt doesn't match it.
        """
        self._load_keys()
        problems: list[str] = []
        prev = GENESIS
        last_seq: Optional[int] = None
        last_hash: Optional[str] = None
        if self.path.exists():
            for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    problems.append(f"line {lineno}: unparseable receipt (corrupt)")
                    prev = None  # the chain cannot link across a broken line
                    continue
                where = f"seq {e['seq']}" if isinstance(e, dict) and "seq" in e else f"line {lineno}"
                try:
                    payload = {k: e[k] for k in _PAYLOAD_KEYS}
                except (KeyError, TypeError):
                    missing = [k for k in _PAYLOAD_KEYS if not (isinstance(e, dict) and k in e)]
                    problems.append(f"{where}: missing field(s) {missing} (tampered)")
                    prev = e.get("entry_hash") if isinstance(e, dict) else None
                    continue
                recomputed = sha256_hex(canonical_json(payload))
                if recomputed != e.get("entry_hash"):
                    problems.append(f"{where}: content hash mismatch (tampered)")
                if e.get("prev_hash") != prev:
                    problems.append(f"{where}: broken chain link")
                try:
                    self._pub.verify(bytes.fromhex(e["signature"]), e["entry_hash"].encode("utf-8"))
                except Exception:
                    problems.append(f"{where}: bad signature")
                prev = e.get("entry_hash")
                last_seq, last_hash = e.get("seq"), e.get("entry_hash")

        if expected_head is not None:
            exp_seq, exp_hash = expected_head
            if last_seq != exp_seq or last_hash != exp_hash:
                found = f"seq {last_seq}" if last_seq is not None else "empty ledger"
                problems.append(
                    f"head mismatch: expected seq {exp_seq} ({exp_hash[:12]}…), "
                    f"found {found} — ledger truncated or rolled back"
                )

        return (len(problems) == 0), problems

    # -- queries ---------------------------------------------------------- #
    def tail(self, n: int = 20) -> list[dict]:
        return self._entries()[-n:]

    def count_allows(self, rule: str, within_seconds: int) -> int:
        """How many times ``rule`` has been allowed within the time window.

        Used by the rate-limit constraint. Counts ``allow`` receipts (the moment
        of authorisation) for the given rule.
        """
        return self._count_allows(rule, within_seconds)

    def _count_allows(self, rule: str, within_seconds: int) -> int:
        from time import time

        cutoff = time() - within_seconds
        count = 0
        for e in self._entries():
            if e.get("rule") != rule or e.get("outcome") != "allow":
                continue
            try:
                ts = datetime.fromisoformat(e["ts"]).timestamp()
            except Exception:
                continue
            if ts >= cutoff:
                count += 1
        return count
