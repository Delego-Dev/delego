"""Regression tests for the 0.2.3 / 0.3.0 security fixes.

C1 — the URL query is folded into the fingerprint preimage (protocol 0.3, spec
§4.2), so the decision itself is bound to the query and brokers forward it;
only a ``#fragment`` — still outside the preimage — is refused.

C2 — query canonicalization follows the spec §4.2 steps exactly (a
parser-differential risk).

H2 — ``Policy.load`` must fail closed on an invalid policy, including rejecting
unknown keys (a misspelled constraint previously failed *open*).
"""

from __future__ import annotations

import textwrap

import pytest

from delego import BrokerRefusal, Policy, PolicyError, ProposedAction
from delego.brokers import NullBroker


def _action(url: str) -> ProposedAction:
    return ProposedAction(instruction="do a thing", method="GET", url=url, params={})


# --- C1: the query is in the fingerprint (0.3); only a fragment is refused ----

def test_fingerprinted_url_keeps_query_strips_fragment():
    a = _action("https://api.example.com/orders?to=me#frag")
    assert a.fingerprinted_url == "https://api.example.com/orders?to=me"
    assert a.has_fragment is True


def test_clean_url_has_no_query_or_fragment():
    a = _action("https://api.example.com/orders")
    assert a.has_query is False
    assert a.has_fragment is False
    assert a.fingerprinted_url == "https://api.example.com/orders"
    assert a.canonical_query == []


def test_query_substitution_changes_the_fingerprint():
    # The 0.2 confused-deputy gap, closed structurally in 0.3: two URLs that
    # differ only in their query no longer share a fingerprint, so an approval
    # for one cannot release the other (spec §4.2, §7).
    me = _action("https://api.example.com/orders?to=me")
    attacker = _action("https://api.example.com/orders?to=attacker")
    assert me.fingerprint != attacker.fingerprint
    # The query is authorised (fingerprint-bound), so a broker executes it.
    rec = NullBroker().execute(me)
    assert rec["status"] == "simulated"


def test_broker_refuses_a_fragment():
    # The fragment stays outside the preimage and is never transmitted, so a
    # value riding it was never authorised — refuse, never silently strip.
    with pytest.raises(BrokerRefusal):
        NullBroker().execute(_action("https://api.example.com/orders#smuggled"))


def test_broker_executes_a_clean_action():
    rec = NullBroker().execute(_action("https://api.example.com/orders"))
    assert rec["status"] == "simulated"


def test_broker_refusal_during_propose_is_audited(firewall):
    # An allowed action whose broker refuses (fragment guard) must still leave
    # a receipt — spec §8: every decision and execution is recorded. Before
    # 0.3.0 the exception propagated with nothing written, so the refusal was
    # invisible in the ledger.
    bad = ProposedAction(
        instruction="read my account details",
        method="GET",
        url="https://api.example.com/accounts/me#smuggled",
        params={},
    )
    with pytest.raises(BrokerRefusal):
        firewall.propose(bad)

    last = firewall.audit.tail(1)[-1]
    assert last["phase"] == "execution" and last["outcome"] == "deny"
    assert any("broker did not execute" in r for r in last["reasons"])
    ok, problems = firewall.audit.verify()
    assert ok, problems


# --- C2 (0.3): query canonicalization follows spec §4.2 exactly ---------------

def test_canonical_query_decodes_sorts_and_preserves_duplicates():
    a = _action("https://api.example.com/x?b=2&a=%41&a=plus+space&a&b=2")
    assert a.canonical_query == [
        ["a", ""],            # no '=' → empty-string value
        ["a", "A"],           # %41 percent-decoded
        ["a", "plus space"],  # '+' decoded as space
        ["b", "2"],           # duplicates preserved, sorted by name then value
        ["b", "2"],
    ]


def test_canonical_query_excludes_fragment_and_handles_empty():
    assert _action("https://api.example.com/x?a=1#b=2").canonical_query == [["a", "1"]]
    assert _action("https://api.example.com/x?").canonical_query == []
    assert _action("https://api.example.com/x").canonical_query == []


def test_equivalent_encodings_share_a_fingerprint():
    # Reordered pairs and %20 vs '+' canonicalize identically — the fingerprint
    # binds the canonical form, not the raw bytes of the query.
    a = _action("https://api.example.com/x?b=two%20words&a=1")
    b = _action("https://api.example.com/x?a=1&b=two+words")
    assert a.canonical_query == b.canonical_query == [["a", "1"], ["b", "two words"]]
    assert a.fingerprint == b.fingerprint


def test_bare_url_fingerprint_carries_empty_query_key():
    # The 0.3 preimage always contains "query" (as []), so every fingerprint
    # differs from its 0.2 value — this is the breaking change of the protocol
    # bump. Recompute the 0.2 preimage by hand and check they differ.
    from delego.util import canonical_json, sha256_hex

    a = _action("https://api.example.com/orders")
    old = sha256_hex(
        canonical_json(
            {"method": "GET", "host": a.host, "path": a.path, "params": a.params}
        )
    )
    assert a.fingerprint != old


# --- H2: an invalid policy fails closed (PolicyError); no silent fail-open ---

def _policy_file(tmp_path, body: str) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def test_valid_policy_loads(tmp_path):
    path = _policy_file(
        tmp_path,
        """
        version: 1
        default: deny
        rules:
          - name: read
            decision: allow
            match: {method: GET, path: /orders}
        """,
    )
    assert Policy.load(path) is not None


def test_unknown_constraint_key_is_rejected(tmp_path):
    # `amount_max` is a typo for the real `amount` constraint. It used to be
    # silently dropped, leaving the rule uncapped (fail-open). Must now raise.
    path = _policy_file(
        tmp_path,
        """
        version: 1
        default: deny
        rules:
          - name: pay
            decision: allow
            match: {method: POST, path: /pay}
            constraints: {amount_max: 5000}
        """,
    )
    with pytest.raises(PolicyError):
        Policy.load(path)


def test_unknown_match_key_is_rejected(tmp_path):
    path = _policy_file(
        tmp_path,
        """
        version: 1
        default: deny
        rules:
          - name: r
            decision: allow
            match: {verb: POST}
        """,
    )
    with pytest.raises(PolicyError):
        Policy.load(path)


def test_invalid_rule_decision_is_rejected(tmp_path):
    path = _policy_file(
        tmp_path,
        """
        version: 1
        default: deny
        rules:
          - name: r
            decision: maybe
            match: {path: /x}
        """,
    )
    with pytest.raises(PolicyError):
        Policy.load(path)
