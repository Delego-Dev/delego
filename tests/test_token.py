"""The §9 authorization token: minting only for `allow`, and the §9.1 verifier.

The verifier is security-critical — JWT algorithm confusion is the classic
footgun — so these pin every failure mode the spec names: EdDSA-only (reject
`none` and HS-style confusion), exact `aud`, expiry, single-use `jti`/`cns`, and
the fingerprint re-check (step 5) that binds a credential release to one action.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

_POLICY_EXAMPLE = Path(__file__).resolve().parent.parent / "policy.example.yaml"

from delego import (
    ProposedAction,
    TokenError,
    TokenIssuer,
    build_firewall,
    require_fingerprint,
    verify_token,
)
from delego.config import Paths
from delego.token import ensure_token_keys
from cryptography.hazmat.primitives import serialization

AUD = "broker:onecli"
FPR = "c70d4ee57957202087887cb5e9d32222977b728bd06947b7761c283b6d4ed394"
IHT = "76f8eef1b97e1213a59eec28cedf15bb999fdb00a3fd17f8343bc4676fdbb4f3"


@pytest.fixture
def issuer(tmp_path):
    return TokenIssuer.from_files(
        tmp_path / "token_key.pem", tmp_path / "token_key.pub", issuer="delego:test"
    )


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


# --- minting is gated to `allow` / released approvals --------------------------

def _fw(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "policy.yaml").write_text(_POLICY_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    return build_firewall(Paths.resolve(home), mint_tokens=True, token_audience=AUD)


def test_allow_mints_a_token_and_it_verifies(tmp_path):
    fw = _fw(tmp_path)
    d = fw.propose(ProposedAction("read my account details", "GET", "https://api.example.com/accounts/me", {}))
    assert d.outcome == "allow" and d.token is not None
    claims = verify_token(d.token, public_key=fw.token_issuer.public_key, audience=AUD)
    assert claims["fpr"] == d.action_fingerprint
    assert claims["iht"] == d.intent_hash
    assert claims["pol"] == {"version": 1, "rule": "read-accounts"}


def test_deny_and_needs_approval_mint_no_token(tmp_path):
    fw = _fw(tmp_path)
    deny = fw.propose(ProposedAction("share", "POST", "https://api.example.com/accounts/me/permissions", {"grant": "x"}))
    assert deny.outcome == "deny" and deny.token is None
    parked = fw.propose(ProposedAction("order", "POST", "https://api.example.com/orders",
                                       {"amount": 100, "currency": "USD", "destination": "internal"}))
    assert parked.outcome == "needs_approval" and parked.token is None


def test_released_approval_mints_a_token(tmp_path):
    fw = _fw(tmp_path)
    order = ProposedAction("place a small order", "POST", "https://api.example.com/orders",
                           {"amount": 2400, "currency": "USD", "destination": "internal"})
    parked = fw.propose(order)
    fw.approvals.decide(parked.approval_id, approved=True, approver="human")
    released = fw.resolve(parked.approval_id, order)
    assert released.outcome == "allow" and released.token is not None
    claims = verify_token(released.token, public_key=fw.token_issuer.public_key, audience=AUD)
    assert claims["apr"] == parked.approval_id


# --- the §9.1 verifier --------------------------------------------------------

def _mint(issuer, **over):
    kw = dict(action_fingerprint=FPR, intent_hash=IHT, audience=AUD, rule="place-order", policy_version=1)
    kw.update(over)
    return issuer.mint(**kw)


def test_valid_token_round_trips(issuer):
    claims = verify_token(_mint(issuer), public_key=issuer.public_key, audience=AUD)
    assert claims["fpr"] == FPR and claims["aud"] == AUD


def test_alg_none_is_rejected(issuer):
    # Strip to an unsigned alg=none token — the classic JWT bypass.
    _, payload, _ = _mint(issuer).split(".")
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{payload}."
    with pytest.raises(TokenError, match="EdDSA"):
        verify_token(forged, public_key=issuer.public_key, audience=AUD)


def test_tampered_payload_fails_signature(issuer):
    header, _, sig = _mint(issuer).split(".")
    swapped = _b64({"iss": "delego:test", "aud": AUD, "iat": 1, "exp": 10**12,
                    "jti": "x", "cns": "y", "fpr": "0" * 64, "iht": IHT})
    with pytest.raises(TokenError, match="signature"):
        verify_token(f"{header}.{swapped}.{sig}", public_key=issuer.public_key, audience=AUD)


def test_wrong_audience_is_rejected(issuer):
    with pytest.raises(TokenError, match="aud"):
        verify_token(_mint(issuer), public_key=issuer.public_key, audience="broker:evil")


def test_expired_token_is_rejected(issuer):
    tok = _mint(issuer, _iat=1_000_000)  # long past; exp = iat + ttl
    with pytest.raises(TokenError, match="expired"):
        verify_token(tok, public_key=issuer.public_key, audience=AUD, now=2_000_000)


def test_ttl_over_max_is_rejected(issuer):
    # Hand-craft a token whose exp - iat exceeds 300s, signed correctly.
    iat = 1_000_000
    header = {"alg": "EdDSA", "typ": "JWT", "kid": issuer.kid}
    claims = {"iss": "delego:test", "aud": AUD, "iat": iat, "exp": iat + 3600,
              "jti": "j", "cns": "c", "fpr": FPR, "iht": IHT}
    si = f"{_b64(header)}.{_b64(claims)}"
    sig = issuer.private_key.sign(si.encode())
    tok = f"{si}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    with pytest.raises(TokenError, match="TTL"):
        verify_token(tok, public_key=issuer.public_key, audience=AUD, now=iat + 1)


def test_jti_replay_and_cns_single_use(issuer):
    seen, consumed = set(), set()
    tok = _mint(issuer)
    verify_token(tok, public_key=issuer.public_key, audience=AUD, seen_jti=seen, consumed_cns=consumed)
    # Same token again: jti is now seen.
    with pytest.raises(TokenError, match="replay"):
        verify_token(tok, public_key=issuer.public_key, audience=AUD, seen_jti=seen, consumed_cns=consumed)
    # A fresh token shares no jti but, if it reused a cns, would be refused.
    tok2 = _mint(issuer, _cns=list(consumed)[0])
    with pytest.raises(TokenError, match="cns"):
        verify_token(tok2, public_key=issuer.public_key, audience=AUD, seen_jti=set(), consumed_cns=consumed)


def test_wrong_key_is_rejected(issuer, tmp_path):
    ensure_token_keys(tmp_path / "other.pem", tmp_path / "other.pub")
    other_pub = serialization.load_pem_public_key((tmp_path / "other.pub").read_bytes())
    with pytest.raises(TokenError, match="signature"):
        verify_token(_mint(issuer), public_key=other_pub, audience=AUD)


def test_key_resolver_selects_by_kid(issuer):
    # kid is taken from the header only to *select among configured keys* — the
    # key itself never comes from the token.
    keys = {issuer.kid: issuer.public_key}
    claims = verify_token(_mint(issuer), key_resolver=keys.get, audience=AUD)
    assert claims["fpr"] == FPR
    with pytest.raises(TokenError, match="no configured key"):
        verify_token(_mint(issuer), key_resolver={}.get, audience=AUD)


# --- step 5: the fingerprint re-check (the #7 closure) ------------------------

def test_require_fingerprint_binds_to_one_exact_action(issuer):
    authorized = ProposedAction("place a small order", "POST", "https://api.example.com/orders",
                                {"amount": 2400, "currency": "USD", "destination": "internal"})
    claims = verify_token(_mint(issuer, action_fingerprint=authorized.fingerprint),
                          public_key=issuer.public_key, audience=AUD)
    require_fingerprint(claims, authorized)  # ok
    # Agent declared one set of params, tries to send another → refused at the PEP.
    substituted = ProposedAction("place a small order", "POST", "https://api.example.com/orders",
                                 {"amount": 2400, "currency": "USD", "destination": "internal", "recipient": "attacker"})
    with pytest.raises(TokenError, match="not the action that was authorized"):
        require_fingerprint(claims, substituted)
