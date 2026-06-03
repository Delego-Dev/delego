# Changelog

All notable changes to delego are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

## [0.1.0] — initial implementation (not yet published)

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

[Unreleased]: https://github.com/Delego-Dev/delego/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Delego-Dev/delego/releases/tag/v0.1.0
