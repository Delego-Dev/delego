# Contributing to delego

Thanks for your interest in delego — a policy & audit firewall for agent
actions. Please read [CLAUDE.md](CLAUDE.md) before making changes: it documents
the design and, above all, the **invariants that must not be broken**.

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
pip install -e ".[dev]"
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

- Keep changes small and focused; explain the *why*.
- Re-run `python examples/demo.py` and `pytest` before submitting.
- Update `README.md`, `CHANGELOG.md`, and the tests alongside any behaviour change.
- Confirm you have not weakened any invariant above.

## Releasing (maintainers)

Releases publish to PyPI from GitHub Actions using **PyPI Trusted Publishing**
(OIDC — no API tokens are stored in the repo). One-time setup: on PyPI, add a
trusted publisher for project `delego` → repo `Delego-Dev/delego`, workflow
`release.yml`, environment `pypi`. Then for each release:

1. Bump `version` in `pyproject.toml` and move the `CHANGELOG.md` entries from
   *Unreleased* into the new version.
2. Publish a GitHub Release with tag `vX.Y.Z`.
3. `.github/workflows/release.yml` builds the sdist + wheel and publishes them.
