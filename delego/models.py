"""The two things that flow through the firewall: a proposed action and a decision.

The two derived values on ``ProposedAction`` are the whole point of the design:

* ``intent_hash`` — a hash of the *original human instruction*. It is carried
  through every receipt so an auditor can later tie an executed action back to
  the request that authorised it. (An OAuth token carries no such commitment.)

* ``fingerprint`` — a hash of the concrete action (method + host + path +
  params). Human approvals are bound to this exact fingerprint, so an agent
  that gets a "yes" for one action cannot reuse it to execute a different one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from .util import canonical_json, sha256_hex

OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_APPROVAL = "needs_approval"


@dataclass
class ProposedAction:
    """What an agent wants to do, plus the instruction it believes authorises it.

    ``params`` are the decision-relevant fields extracted from the request
    (e.g. ``{"amount": 2400, "currency": "USD", "destination": "internal"}``).
    The firewall evaluates constraints against these, so the agent must declare
    them honestly — they are also what gets fingerprinted and audited.
    """

    instruction: str
    method: str
    url: str
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc.lower()

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def has_query(self) -> bool:
        """Whether ``url`` carries a query string or fragment.

        Through protocol 0.2 the fingerprint covers only method+host+path+params
        (spec §4.2): the URL's query string is **not** part of the action's
        identity. A query or fragment therefore carries data the firewall never
        authorised — e.g. ``/orders?to=me`` and ``/orders?to=attacker`` share one
        fingerprint. A broker MUST NOT forward it (spec §4.2); it executes only
        the fingerprinted URL (:attr:`fingerprinted_url`) and refuses a stray
        query rather than smuggling decision-relevant data past the decision.
        """
        parts = urlsplit(self.url)
        return bool(parts.query) or bool(parts.fragment)

    @property
    def fingerprinted_url(self) -> str:
        """The URL a broker may actually request: scheme + host + path only.

        This is the exact slice of ``url`` that the fingerprint commits to
        (host + path; method and params travel separately). Any query string or
        fragment on ``url`` is dropped, because it is not represented in the
        fingerprint and so was never authorised (see :attr:`has_query`).
        """
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    @property
    def intent_hash(self) -> str:
        return sha256_hex(canonical_json({"instruction": self.instruction.strip()}))

    @property
    def fingerprint(self) -> str:
        return sha256_hex(
            canonical_json(
                {
                    "method": self.method.upper(),
                    "host": self.host,
                    "path": self.path,
                    "params": self.params,
                }
            )
        )

    def summary(self) -> str:
        tail = f" {canonical_json(self.params)}" if self.params else ""
        return f"{self.method.upper()} {self.host}{self.path}{tail}"


@dataclass
class Decision:
    """The firewall's verdict on a proposed action."""

    outcome: str  # one of OUTCOME_ALLOW / OUTCOME_DENY / OUTCOME_APPROVAL
    rule: Optional[str]
    reasons: list[str]
    intent_hash: str
    action_fingerprint: str
    approval_id: Optional[str] = None
    executed: bool = False
    result: Optional[dict] = None

    @property
    def allowed(self) -> bool:
        return self.outcome == OUTCOME_ALLOW
