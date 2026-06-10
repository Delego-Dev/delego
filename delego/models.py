"""The two things that flow through the firewall: a proposed action and a decision.

The two derived values on ``ProposedAction`` are the whole point of the design:

* ``intent_hash`` — a hash of the *original human instruction*. It is carried
  through every receipt so an auditor can later tie an executed action back to
  the request that authorised it. (An OAuth token carries no such commitment.)

* ``fingerprint`` — a hash of the concrete action (method + host + path +
  canonicalized query + params). Human approvals are bound to this exact
  fingerprint, so an agent that gets a "yes" for one action cannot reuse it to
  execute a different one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import unquote_plus, urlsplit, urlunsplit

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

        Since protocol 0.3 the query **is** part of the fingerprint (see
        :attr:`canonical_query`), so a query-bearing URL is fully represented in
        the action's identity and a broker may forward it. The fragment never
        is — it is excluded from the preimage (spec §4.2) and from
        :attr:`fingerprinted_url`; brokers refuse it (:attr:`has_fragment`).
        Kept for backward compatibility with 0.2-era broker adapters.
        """
        parts = urlsplit(self.url)
        return bool(parts.query) or bool(parts.fragment)

    @property
    def has_fragment(self) -> bool:
        """Whether ``url`` carries a ``#fragment``.

        The fragment is excluded from the fingerprint preimage (spec §4.2) and
        is never transmitted upstream, so a value riding it was never
        authorised: brokers refuse rather than silently strip it.
        """
        return bool(urlsplit(self.url).fragment)

    @property
    def canonical_query(self) -> list[list[str]]:
        """The URL query as the canonical ``[name, value]`` list (spec §4.2).

        The steps are exact — query canonicalization is a parser-differential
        risk — and implemented mechanically: take the query component (after the
        first ``?``, before any ``#``; absent or empty → ``[]``); split on ``&``;
        split each raw pair on its **first** ``=`` (no ``=`` → value ``""``);
        percent-decode per RFC 3986 with ``+`` as space; sort by name then value
        by Unicode code point, preserving duplicates. An empty raw segment (as
        in ``?a=1&&b=2``) is kept as ``["", ""]`` — over-distinguishing URLs is
        safe, collapsing them is not.
        """
        q = urlsplit(self.url).query
        if not q:
            return []
        pairs = []
        for raw in q.split("&"):
            name, _, value = raw.partition("=")
            pairs.append([unquote_plus(name), unquote_plus(value)])
        pairs.sort()
        return pairs

    @property
    def fingerprinted_url(self) -> str:
        """The URL a broker may actually request: scheme + host + path + query.

        This is the exact slice of ``url`` that the fingerprint commits to
        (host + path + query; method and params travel separately). Any
        ``#fragment`` is excluded, because it is not represented in the
        fingerprint and so was never authorised (see :attr:`has_fragment`).
        """
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

    @property
    def intent_hash(self) -> str:
        return sha256_hex(canonical_json({"instruction": self.instruction.strip()}))

    @property
    def fingerprint(self) -> str:
        # The protocol 0.3 preimage (spec §4.2): the canonical query is always
        # present ("query": [] for a bare URL), binding the *executed* query to
        # the *proposed* one. Policy constraints still evaluate params only.
        return sha256_hex(
            canonical_json(
                {
                    "method": self.method.upper(),
                    "host": self.host,
                    "path": self.path,
                    "params": self.params,
                    "query": self.canonical_query,
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
