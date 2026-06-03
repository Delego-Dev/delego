"""Human-in-the-loop approval queue.

When the policy says ``needs_approval``, the firewall parks the action here and
a human decides out-of-band (via the CLI: ``delego approve <id>``). Each record
is bound to the action's fingerprint, so an approval can only ever release the
*exact* action it was granted for.

v0.1 storage is an append-only JSONL file (last record per id wins). It's
deliberately simple and inspectable; a real deployment would put this behind
the daemon with proper access control.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Optional

from .util import now_iso

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"


class ApprovalStore:
    def __init__(self, path):
        self.path = Path(path)

    def _read(self) -> dict[str, dict]:
        records: dict[str, dict] = {}
        if not self.path.exists():
            return records
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                records[rec["id"]] = rec  # later (decided) records overwrite earlier ones
        return records

    def _append(self, rec: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def create(self, *, action_fingerprint: str, intent_hash: str, summary: str) -> str:
        approval_id = "apr_" + secrets.token_hex(6)
        self._append(
            {
                "id": approval_id,
                "status": STATUS_PENDING,
                "action_fingerprint": action_fingerprint,
                "intent_hash": intent_hash,
                "summary": summary,
                "created_at": now_iso(),
                "decided_at": None,
                "approver": None,
            }
        )
        return approval_id

    def get(self, approval_id: str) -> Optional[dict]:
        return self._read().get(approval_id)

    def decide(self, approval_id: str, approved: bool, approver: str = "cli") -> Optional[dict]:
        rec = self.get(approval_id)
        if rec is None:
            return None
        if rec["status"] != STATUS_PENDING:
            return rec  # already decided; idempotent
        updated = {
            **rec,
            "status": STATUS_APPROVED if approved else STATUS_DENIED,
            "decided_at": now_iso(),
            "approver": approver,
        }
        self._append(updated)
        return updated

    def pending(self) -> list[dict]:
        return [r for r in self._read().values() if r["status"] == STATUS_PENDING]
