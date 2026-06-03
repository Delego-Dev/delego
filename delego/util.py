"""Small, dependency-light helpers shared across the package.

Everything that gets hashed or signed goes through ``canonical_json`` so the
byte representation is stable and reproducible (sorted keys, no insignificant
whitespace). If two processes serialise the same object they MUST get the same
bytes, otherwise the audit chain and the action fingerprints won't verify.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, UTF-8 preserved."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string (used for receipts/approvals)."""
    return datetime.now(timezone.utc).isoformat()
