"""Regression tests for the 0.2.3 security fixes.

C1 — brokers must refuse an unauthorised query string (the confused-deputy gap:
through protocol 0.2 the query is outside the fingerprint, so a value riding it
was never authorised).

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


# --- C1: the query string is outside the fingerprint; brokers must refuse it ---

def test_fingerprinted_url_strips_query_and_fragment():
    a = _action("https://api.example.com/orders?to=attacker#frag")
    assert a.fingerprinted_url == "https://api.example.com/orders"
    assert a.has_query is True


def test_clean_url_has_no_query():
    a = _action("https://api.example.com/orders")
    assert a.has_query is False
    assert a.fingerprinted_url == "https://api.example.com/orders"


def test_query_substitution_shares_one_fingerprint_but_broker_refuses():
    me = _action("https://api.example.com/orders?to=me")
    attacker = _action("https://api.example.com/orders?to=attacker")
    # The query is not in the 0.2 preimage, so both fingerprint identically...
    assert me.fingerprint == attacker.fingerprint
    # ...which is exactly why a broker must refuse rather than forward the query.
    with pytest.raises(BrokerRefusal):
        NullBroker().execute(attacker)
    with pytest.raises(BrokerRefusal):
        NullBroker().execute(me)


def test_broker_executes_a_clean_action():
    rec = NullBroker().execute(_action("https://api.example.com/orders"))
    assert rec["status"] == "simulated"


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
