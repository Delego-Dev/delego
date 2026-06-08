# Security Policy

delego is a security tool — intent-bound action authorization for AI agents that
authorises an agent's action *before* a credential is used, and leaves a
tamper-evident receipt. We take vulnerabilities seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/Delego-Dev/delego/security/advisories/new),
or email **koishore@gmail.com**. Include a description, the affected version or
commit, and reproduction steps. We aim to acknowledge within 72 hours.

## In scope

Issues that undermine delego's guarantees, for example:

- A path that authorises an action the policy should deny (bypassing the
  forbidden → rules → default order, or a fail-closed constraint).
- An approval for one action releasing a *different* action — i.e. a break in
  the confused-deputy guard or the action-fingerprint binding.
- Tampering with the audit ledger that `verify()` fails to detect, or any way to
  forge a receipt, its hash chain, or its Ed25519 signature.
- Any way to make the authorization decision depend on an LLM or other
  non-deterministic input.

## Out of scope

- The default `NullBroker` makes no real requests and holds no credentials.
  Credential handling lives in whatever broker you wire in behind the
  `BrokerAdapter` interface — report those against the broker.
- Vulnerabilities in third-party dependencies (report upstream), unless delego
  uses them unsafely.

## Threat model & known limitations

Be precise about what delego does and does not protect against:

- **delego authorises the agent's *declared* action, not the bytes on the wire.**
  The agent supplies `params`, `url`, and `instruction`; delego trusts them. Its
  guarantees hold only if your broker executes exactly the fingerprinted action.
  delego is a control only when the credential is reachable **solely** through the
  broker — an agent with raw network/exec can bypass it entirely.
- **The recorded intent is the agent's claim.** `intent_hash` binds the
  instruction the agent *reported*; it is not verified against the real human
  request, so under a fully compromised agent the audited intent is
  attacker-chosen.
- **Audit tamper-evidence has limits.** Hash-chaining detects edits, reordering,
  and middle deletions, but **not truncation of the most recent receipts** (a
  tail-truncated prefix verifies clean). Use `verify(expected_head=…)` with an
  externally-anchored head to detect rollback. The Ed25519 signing key is stored
  locally; anyone who can read it (e.g. after host compromise) can forge the
  chain. Use an HSM/KMS and/or an external transparency anchor for high assurance.

These are design boundaries, not accepted bugs — a *bypass within* these
boundaries (e.g. a constraint that fails open, like a non-finite amount slipping
a cap) is in scope above.

## Supported versions

delego is pre-1.0; only the latest released version receives security fixes.
