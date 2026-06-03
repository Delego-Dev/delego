# Security Policy

delego is a security tool — a policy & audit firewall that authorises an agent's
action *before* a credential is used, and leaves a tamper-evident receipt. We
take vulnerabilities seriously.

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

## Supported versions

delego is pre-1.0; only the latest released version receives security fixes.
