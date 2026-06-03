# Changelog

All notable changes to delego are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-06-04

First public release on PyPI. (0.1.0 was the initial implementation and was never
published.) Implements wire-protocol **0.2.0**; see
[`__protocol_version__`](delego/__init__.py).

### Security
- **Single-use approvals.** A human approval now releases its action exactly
  once: `engine.resolve` consumes the approval before executing, so a replayed
  `resolve` of an already-used approval is refused (`approved` → `consumed`).
  Previously one approval could be resolved repeatedly, executing the same action
  N times.
- **Approvals are bound to the instruction, not only the action fingerprint.**
  `resolve` re-checks the approval's `intent_hash`, so the same action carried
  under a different claimed instruction is denied.
- **Rate limits fail closed when unevaluable.** A `rate_limit` constraint with no
  audit log to read now denies instead of silently passing.
- **`rate_limit` on `needs_approval` rules now counts.** Approved-then-executed
  actions carry their originating rule on the execution receipt, so the
  ledger-backed counter attributes them correctly (previously `rule=None`, making
  the cap a no-op).
- **`verify()` is robust to structural tampering.** Removing a field from a
  receipt, or corrupting a line, is now reported as a problem instead of crashing
  verification.

### Added
- Regression tests for the above: single-use approvals, intent-bound resolve,
  fail-closed rate limit without an audit log, and crash-free `verify()` on a
  removed field (`tests/test_guards.py`).
- `delego pending` now prints the originating instruction for each parked action,
  so the human approver sees *what* they are authorising, not just the request.
- pytest regression suite encoding the eight demo scenarios plus invariant
  guards, with an isolated-firewall fixture (`tests/`).
- GitHub Actions CI running the suite **and** the demo on Python 3.10–3.12
  (`.github/workflows/ci.yml`).
- PyPI release workflow using Trusted Publishing (`.github/workflows/release.yml`).
- `delego/__init__.py` exporting the public API (`ProposedAction`, `Decision`,
  `Firewall`, `Policy`, `AuditLog`, `Paths`, `build_firewall`, and the
  `OUTCOME_*` constants).
- Project-scoped state for Claude Code: `Paths.resolve` precedence is now
  `--home` → `DELEGO_HOME` → project-local `./.claude/.delego` (if present) →
  `~/.delego`; added a `delego home` command and a `.gitignore` written into the
  home so the signing key and ledger are never committed.
- Open-source scaffolding: `LICENSE` (Apache-2.0), `CONTRIBUTING.md`,
  `SECURITY.md`, this changelog, and publishing metadata in `pyproject.toml`.

### Changed
- Repository restructured to the standard Python layout (package under
  `delego/`, project files and `examples/demo.py` at the repo root) so
  `pip install -e .` and `python examples/demo.py` work as documented.
- Replaced the BFSI-flavoured example with a generic `api.example.com` example
  across the policy, demo, tests, and docs.
- Retired the committed `CLAUDE.md`; durable design notes now live in
  `ARCHITECTURE.md`. Added `delego.__protocol_version__` (the wire-protocol
  version this reference implements, which must stay ≤ the spec's version) and a
  spec-first / AI-assisted-contribution policy plus a PR template.

## 0.1.0 — initial implementation (never released to PyPI)

### Added
- Deterministic policy engine: forbidden → rules (first match wins) → default,
  with `amount`, `allow_list`, and `rate_limit` constraints, all fail-closed.
- Intent hashing and action fingerprinting (`models.py`).
- Action-bound human approval queue and the confused-deputy guard
  (`engine.resolve`).
- Append-only, hash-chained, Ed25519-signed audit ledger with `verify()`.
- The `delego` CLI (init / policy / pending / approve / deny / log / verify) and
  a FastMCP server exposing propose / resolve / audit_tail / show_policy.
- `NullBroker` (default; holds no credentials) and an `HTTPProxyBroker` sketch.

[Unreleased]: https://github.com/Delego-Dev/delego/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Delego-Dev/delego/releases/tag/v0.2.0
