"""The §9 authorization token — a portable, signed PDP→PEP decision artifact.

The token is **not** delego's load-bearing control (that is the deterministic
decision, the fingerprint/intent binding, single-use approval, the audit chain,
and the PDP/PEP split). It is an *optional profile*: a way to carry a `allow`
verdict across a process or network boundary so a **separated** broker (PEP) can
verify "this exact action is authorized right now" without re-consulting the
authorizer (PDP). When the broker is in-process and already trusts the decision,
you don't need it.

It is a compact **JWS / JWT** with `alg = EdDSA` (Ed25519). We build the compact
serialization here on `cryptography` (already a dependency) rather than pulling in
a JWT library: a security tool's token path should be short and auditable, and it
sidesteps the system-PyJWT conflicts the optional `mcp` extra already has to dodge.

Two halves:

* :class:`TokenIssuer` mints a token when the Authorizer renders `allow` (or
  releases a human-approved action). Minting for any other outcome is a bug —
  the issuer only mints for the two it is asked to.
* :func:`verify_token` is the broker side, and the crux. It performs the §9.1
  checks 1–4 (pin EdDSA / reject ``none`` and algorithm confusion; exact ``aud``;
  ``exp``; single-use ``jti`` and ``cns``). Check 5 — recomputing the
  ``action_fingerprint`` of the request the broker is *about to send* and
  requiring it equals ``fpr`` — is :func:`require_fingerprint`, called by the
  broker against the concrete action. That binding is what makes the token bind a
  credential injection to *that exact action*, not merely "something in policy".

**Key separation (spec §9 SHOULD).** The token signing key is distinct from the
audit-chain key: the two have different lifetimes and blast radii, and a
token-minting compromise must not also forge audit history.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .util import canonical_json, sha256_hex

# Spec §9: TTL SHOULD be <= 60s and MUST NOT exceed 300s.
DEFAULT_TTL_SECONDS = 45
MAX_TTL_SECONDS = 300

# The claims a conformant token MUST carry (schema/authorization-token.json).
_REQUIRED_CLAIMS = ("iss", "aud", "iat", "exp", "jti", "cns", "fpr", "iht")


class TokenError(ValueError):
    """A token could not be minted, or failed verification.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers treat a
    bad token as a bad request. A broker that catches this **MUST NOT** inject a
    credential — verification failing is a fail-closed deny, never a soft pass.
    """


# --------------------------------------------------------------------------- #
# base64url (no padding) — the JOSE encoding
# --------------------------------------------------------------------------- #
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _kid_for(pub: Ed25519PublicKey) -> str:
    """A stable key id: the first 16 hex of the SHA-256 of the public key's raw
    bytes. Lets a verifier select among configured keys and supports rotation."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sha256_hex(raw.hex())[:16]


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #
def ensure_token_keys(priv_path: Path, pub_path: Path) -> None:
    """Generate a token signing keypair if one doesn't exist.

    Deliberately a *separate* file from the audit signing key (spec §9): a
    token-minting compromise must not be able to forge the audit chain.
    """
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


# --------------------------------------------------------------------------- #
# minting
# --------------------------------------------------------------------------- #
@dataclass
class TokenIssuer:
    """Mints short-lived authorization tokens for `allow` decisions.

    Construct with the issuer identity and the *token* signing key (not the audit
    key). ``mint`` is called by the Firewall only when it renders `allow` or
    releases an approved action; it is never called for any other outcome.
    """

    issuer: str
    private_key: Ed25519PrivateKey
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    @classmethod
    def from_files(cls, priv_path, pub_path, *, issuer: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        ensure_token_keys(Path(priv_path), Path(pub_path))
        priv = serialization.load_pem_private_key(Path(priv_path).read_bytes(), password=None)
        return cls(issuer=issuer, private_key=priv, ttl_seconds=ttl_seconds)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def kid(self) -> str:
        return _kid_for(self.public_key)

    def mint(
        self,
        *,
        action_fingerprint: str,
        intent_hash: str,
        audience: str,
        approval_id: Optional[str] = None,
        subject: Optional[str] = None,
        policy_version: Optional[int] = None,
        rule: Optional[str] = None,
        # Test/vector hooks: pin the otherwise time/random fields so a CTK
        # vector is byte-reproducible. Never set these in production.
        _iat: Optional[int] = None,
        _jti: Optional[str] = None,
        _cns: Optional[str] = None,
    ) -> str:
        """Mint a compact JWS for an authorized action. Returns the token string.

        TTL is clamped to ``MAX_TTL_SECONDS`` (spec: MUST NOT exceed 300s).
        ``jti`` (replay id) and ``cns`` (consumption nonce) are unique per call.
        """
        ttl = min(self.ttl_seconds, MAX_TTL_SECONDS)
        iat = _iat if _iat is not None else _now_epoch()
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": audience,
            "iat": iat,
            "exp": iat + ttl,
            "jti": _jti or secrets.token_hex(16),
            "cns": _cns or secrets.token_hex(16),
            "fpr": action_fingerprint,
            "iht": intent_hash,
        }
        if approval_id is not None:
            claims["apr"] = approval_id
        if subject is not None:
            claims["sub"] = subject
        if policy_version is not None or rule is not None:
            claims["pol"] = {"version": policy_version, "rule": rule}

        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.kid}
        signing_input = f"{_b64url(canonical_json(header).encode())}.{_b64url(canonical_json(claims).encode())}"
        sig = self.private_key.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(sig)}"


# --------------------------------------------------------------------------- #
# verification (the broker side, §9.1)
# --------------------------------------------------------------------------- #
def verify_token(
    token: str,
    *,
    public_key: Ed25519PublicKey | None = None,
    key_resolver: Callable[[str], Ed25519PublicKey] | None = None,
    audience: str,
    now: int | None = None,
    leeway: int = 60,
    seen_jti: "set[str] | None" = None,
    consumed_cns: "set[str] | None" = None,
    max_ttl: int = MAX_TTL_SECONDS,
) -> dict[str, Any]:
    """Verify a token per spec §9.1 steps 1–4 and return its validated claims.

    Raises :class:`TokenError` on any failure — a broker that catches it **MUST
    NOT** inject a credential. This does **not** perform step 5 (the fingerprint
    re-check); call :func:`require_fingerprint` with the concrete action the
    broker is about to send.

    Key selection is by **verifier configuration**, never the token: pass a
    single ``public_key``, or a ``key_resolver`` mapping the header ``kid`` to a
    key *from your own key set*. The header's ``alg`` is never trusted to decide
    how to verify — EdDSA is pinned and ``none`` (and anything else) is rejected.
    That is the JWT algorithm-confusion defense (spec §9.1 step 1, §11).

    ``seen_jti`` / ``consumed_cns``, if given, are checked for replay and, on
    success, the token's ``jti``/``cns`` are added to them (so a second
    verification of the same token is refused). Pass shared, persisted sets in a
    real deployment; each is retained until at least the token's ``exp``.
    """
    if public_key is None and key_resolver is None:
        raise TokenError("verify_token requires public_key or key_resolver")

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token: expected three dot-separated segments")
    header_b64, payload_b64, sig_b64 = parts

    # --- 1. header: pin EdDSA, reject `none`/confusion; key from OUR config --- #
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        raise TokenError(f"unparseable token header: {e}") from e
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        # Covers alg="none", alg="HS256" (key-confusion), or a missing alg.
        raise TokenError(f"token alg must be EdDSA, got {header.get('alg')!r} (algorithm-confusion guard)")
    if key_resolver is not None:
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise TokenError("token header missing 'kid' but a key_resolver was given")
        try:
            key = key_resolver(kid)
        except Exception as e:
            raise TokenError(f"no configured key for kid {kid!r}: {e}") from e
        if key is None:
            raise TokenError(f"no configured key for kid {kid!r}")
    else:
        key = public_key

    # --- signature over the exact signing input --- #
    try:
        key.verify(_b64url_decode(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii"))
    except InvalidSignature as e:
        raise TokenError("bad token signature") from e
    except Exception as e:
        raise TokenError(f"signature verification error: {e}") from e

    # --- claims --- #
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise TokenError(f"unparseable token claims: {e}") from e
    if not isinstance(claims, dict):
        raise TokenError("token claims must be a JSON object")
    missing = [c for c in _REQUIRED_CLAIMS if c not in claims]
    if missing:
        raise TokenError(f"token missing required claim(s): {missing}")

    # --- 2. exp / aud --- #
    now = now if now is not None else _now_epoch()
    iat, exp = claims["iat"], claims["exp"]
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise TokenError("token iat/exp must be integers (epoch seconds)")
    if exp - iat > max_ttl:
        raise TokenError(f"token TTL {exp - iat}s exceeds the {max_ttl}s maximum")
    if now >= exp + leeway:
        raise TokenError("token has expired")
    if now < iat - leeway:
        raise TokenError("token used before its issued-at time (clock skew beyond leeway)")
    if claims["aud"] != audience:
        # Exact match only — no wildcard, no prefix (spec §9.1 step 2).
        raise TokenError(f"token aud {claims['aud']!r} != this broker's identifier {audience!r}")

    # --- 3. jti replay / 4. cns single-use --- #
    if seen_jti is not None and claims["jti"] in seen_jti:
        raise TokenError("token jti already seen (replay)")
    if consumed_cns is not None and claims["cns"] in consumed_cns:
        raise TokenError("token cns already consumed (single-use)")

    if seen_jti is not None:
        seen_jti.add(claims["jti"])
    if consumed_cns is not None:
        consumed_cns.add(claims["cns"])
    return claims


def require_fingerprint(claims: dict[str, Any], action) -> None:
    """Spec §9.1 step 5 — the point of the token.

    Recompute the ``action_fingerprint`` of the request the broker is about to
    send and require it equals the token's ``fpr``. A token minted for action A
    cannot release action B, even if both are in policy scope — and an agent that
    declared one set of params but tries to send another is refused here, the
    enforcement-side closure of the "declared vs. sent" gap.

    Raises :class:`TokenError` on mismatch; the broker **MUST NOT** inject.
    """
    if action.fingerprint != claims.get("fpr"):
        raise TokenError(
            "action fingerprint does not match the token's fpr: the request the "
            "broker is about to send is not the action that was authorized"
        )
