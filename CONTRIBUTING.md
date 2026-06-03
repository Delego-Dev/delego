# Contributing to delego

Thanks for your interest in delego — a policy & audit firewall for agent
actions. Please read [ARCHITECTURE.md](ARCHITECTURE.md) before making changes: it
documents the design and, above all, the **invariants that must not be broken**.

## Design invariants (do not violate)

delego is a security tool; these properties are the reason it exists. A change
that breaks one breaks the product:

1. **No LLM in the authorization path.** Authorisation is pure, inspectable
   Python (`policy.py`, `engine.py`).
2. **delego holds no credentials** and makes no upstream request itself —
   execution is delegated through a `BrokerAdapter`.
3. **Fail closed.** Default is `deny`; a matched rule whose constraints fail
   becomes a deny, never a silent allow.
4. **Approvals are bound to the exact action fingerprint** (the confused-deputy
   guard in `engine.resolve`).
5. **The audit ledger is append-only, hash-chained, and Ed25519-signed.**
6. **Evaluation order is fixed:** forbidden → rules (first match wins) → default.

If a change seems to require breaking one of these, stop and open an issue first.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/Delego-Dev/delego
cd delego
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # tests; add the `mcp` extra to run the server:
pip install -e ".[dev,mcp]"      # `mcp` is optional, kept out of the core deps
```

## Running the demo and tests

The demo is the de facto spec; the test suite encodes it as regression tests.

```bash
python examples/demo.py     # 8 scenarios + tamper detection
pytest                      # the regression suite
```

CI runs both on Python 3.10, 3.11, and 3.12 (`.github/workflows/ci.yml`). Every
behaviour change must keep the demo green and add or adjust tests to match.

## Pull requests

- **Fork the repository** and open the PR from a branch in your fork; direct
  pushes are not accepted.
- Keep changes small and focused; explain the *why*.
- Re-run `python examples/demo.py` and `pytest` before submitting.
- Update `README.md`, `CHANGELOG.md`, and the tests alongside any behaviour change.
- Confirm you have not weakened any invariant above.
- Fill in the pull-request template completely, including the AI-assistance
  disclosure (below).

## Tests are required

Every behaviour or feature change MUST ship with tests that pin the new
behaviour — a regression test for a fix, a scenario/guard test for a feature
(`tests/test_scenarios.py`, `tests/test_guards.py`). A PR that changes behaviour
without tests will not be merged; if you believe a change genuinely needs none
(pure docs, comments), say so explicitly in the PR. CI runs the suite and the
demo on Python 3.10–3.12.

## The spec leads this implementation

The wire protocol is defined in
[Delego-Dev/specification](https://github.com/Delego-Dev/specification), and the
spec **leads** this code: a normative behaviour is specified there first, then
implemented here. A change to authorization, the audit chain, fingerprinting, or
approval semantics should land in the spec (with regenerated CTK vectors) before
or alongside the implementation. This repo exposes `delego.__protocol_version__`
(the highest protocol version it implements); it MUST stay ≤ the spec's version,
which the spec repo's `conformance.py` enforces by replaying the CTK vectors
against this reference.

## AI-assisted contributions

AI coding assistants are welcome tools, but AI-generated or AI-assisted
contributions to a security tool carry extra risk, so:

- **Disclose it.** The PR template has a required field for whether and how AI was
  used. Be honest and specific.
- **Expect stricter review.** AI-assisted PRs — especially ones touching the
  decision/audit core or an invariant — receive closer scrutiny and may take
  longer to merge. Unreviewed, bulk-generated PRs will be closed.
- **You are accountable.** The human author is responsible for every line: that it
  is correct, tested, and weakens no invariant or security property. "The model
  wrote it" is not a defence.
- **Process is the same — fork, template, tests, green CI.** No fast path for AI
  output.

## Releasing (maintainers)

Releases publish to PyPI from GitHub Actions using **PyPI Trusted Publishing**
(OIDC — no API tokens are stored in the repo). One-time setup: on PyPI, add a
trusted publisher for project `delego` → repo `Delego-Dev/delego`, workflow
`release.yml`, environment `pypi`. Then for each release:

1. Bump `version` in `pyproject.toml` and move the `CHANGELOG.md` entries from
   *Unreleased* into the new version.
2. Publish a GitHub Release with tag `vX.Y.Z`.
3. `.github/workflows/release.yml` builds the sdist + wheel and publishes them.
