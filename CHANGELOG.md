# Changelog

All notable changes to delego are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3] — 2026-06-11

Implements the **§9 authorization token** (optional profile). Protocol unchanged
(still 0.3) — the token is additive and changes no hashed or signed bytes; it's
off by default, so existing deployments are byte-for-byte unchanged.

### Added
- **`delego.token`** — a portable, signed PDP→PEP decision artifact (spec §9):
  a compact JWS / JWT with `alg = EdDSA`. Built on `cryptography` (already a
  dependency) — **no new dependency**, no PyJWT.
  - **`TokenIssuer`** mints a short-lived token (TTL ≤ 300s, default 45s) for an
    `allow` outcome or a released approval — and *only* those; `deny`,
    `needs_approval`, `denied`, and `consumed` mint nothing.
  - **`verify_token`** performs §9.1 checks 1–4: pins `EdDSA` and rejects
    `none`/algorithm-confusion (the key comes from verifier config, never the
    token header), exact `aud` match, expiry with bounded clock skew, and
    single-use `jti` (replay) and `cns` (consumption nonce).
  - **`require_fingerprint`** is §9.1 step 5 — the crux: a broker recomputes the
    fingerprint of the request it's about to send and requires it equals the
    token's `fpr`. This is the enforcement-side closure of the "declared vs.
    sent" gap (a token minted for action A cannot release action B).
- **`Firewall(token_issuer=..., token_audience=...)`** and
  **`build_firewall(..., mint_tokens=True)`** wire the profile; the minted token
  rides on `Decision.token`. A **separate** token signing key
  (`token_key.pem`, distinct from the audit key per spec §9) is generated on
  first use.
- Brokers accept an optional `token=` keyword (non-breaking — a bare
  `execute(action)` adapter still works); `HTTPProxyBroker` forwards the token to
  the gateway as `authorization_token` so the separated PEP can verify it.
- Exports: `TokenIssuer`, `verify_token`, `require_fingerprint`, `TokenError`.

## [0.3.2] — 2026-06-10

Packaging only; protocol unchanged (still 0.3). No functional or API changes.

### Changed
- Project metadata links the website: `[project.urls]` Homepage →
  [delegohq.com](https://delegohq.com) (with Documentation and Changelog
  pages), README links the site, and the MCP Registry entry (`server.json`)
  carries `websiteUrl`. Released so the links appear on the live PyPI page
  and registry entry.

## [0.3.1] — 2026-06-10

UX patch from live MCP testing; protocol unchanged (still 0.3).

### Changed
- **MCP tools return structured data.** Tool results are dicts/lists (FastMCP
  structured content) instead of JSON-encoded strings inside JSON — agents no
  longer parse twice.
- **A broker refusal over MCP is deny-shaped, not an exception.** Proposing an
  allowed action whose URL carries a `#fragment` now returns
  `outcome: "deny", executed: false` with the refusal reason (the receipt was
  already written since 0.3.0); previously the `BrokerRefusal` surfaced as a
  raw tool error.
- **An uninitialised home is a structured `setup_required` payload over MCP**
  (with the exact `delego init` command), not a stack trace. Initialisation
  stays deliberate — the server does not silently generate signing keys.
- **Mismatch denials name what the approval was issued for.** A
  fingerprint/intent mismatch on `resolve` includes the approved action's
  summary (or instruction), so a caller that drifted a parameter can
  self-correct. Nothing new is revealed — the summary is already visible via
  `delego pending` and the ledger.
- **`delego approve`/`deny` echo the action and instruction** being decided —
  the human consent moment shows *what* was authorised, not just an id.

### Added
- **`delego_pending` MCP tool** — a read-only list of parked approvals (id,
  summary, instruction, rule, fingerprint, created_at). Approve/deny remain
  deliberately absent from the MCP surface: the agent that proposed an action
  must never be able to approve it.
- **`delego verify --anchor-file PATH`** — checks the chain against the head
  stored in the file and, only after a clean verify, advances it to the
  current head. Makes §8.3 head-anchoring a one-flag habit; a failed verify
  never advances the anchor.
- The `dev` extra now includes `mcp`, so CI exercises the MCP facade
  (`tests/test_mcp_server.py`; skips gracefully where `mcp` is absent).

## [0.3.0] — 2026-06-10

Implements wire **protocol 0.3** (`__protocol_version__ = "0.3"`).

### Changed — BREAKING
- **The URL query string is folded into the `action_fingerprint` preimage**
  (spec §4.2). The query is canonicalized exactly as specified (split on `&`,
  first-`=` split, RFC 3986 percent-decoding with `+` as space, sort by
  name-then-value by code point, duplicates preserved, fragment excluded) and
  the preimage always carries a `"query"` key (`[]` for a bare URL) — so
  **every fingerprint changes**, including for URLs with no query. This closes
  the confused-deputy gap where `/orders?to=me` and `/orders?to=attacker`
  shared one fingerprint: the *decision* — not merely the broker — is now bound
  to the query. Approvals parked by ≤ 0.2.x no longer match (they deny,
  fail-closed); re-propose them. The `hashing` and `resolve` CTK vectors are
  regenerated in the specification repo. Policy constraints still evaluate
  `params` only — decision-relevant values MUST travel in `params`.
- **Brokers now forward the query of an authorised action.** Since the query is
  fingerprint-bound, `ProposedAction.fingerprinted_url` includes it
  (scheme+host+path+query); brokers refuse only a `#fragment` (still outside
  the preimage; `BrokerRefusal`, never a silent strip). New
  `ProposedAction.has_fragment` and `.canonical_query`; `has_query` is kept for
  0.2-era adapters. A 0.2.3-style broker that still refuses all queries remains
  safe — just over-strict.

### Fixed
- **Every refusal and execution now leaves a receipt (audit completeness,
  spec §7/§8).** Two paths previously returned/raised without writing to the
  ledger: (1) `resolve()` with an **unknown approval id** denied silently —
  an attacker could probe approval ids without leaving evidence; it is now
  recorded as an `execution`/`deny` receipt like every other refusal in the
  resolve flow. (2) A **broker refusal or failure** during execution
  propagated with nothing written — the allow decision and the failure were
  both invisible in the ledger (including the broker's own `BrokerRefusal`
  guard). `_execute` now records an `execution`/`deny` receipt with the
  broker's reason before re-raising.
- **Rate limits actually hold under concurrency now.** The 0.2.3 changelog
  claimed the evaluate→execute→append sequence was serialized under the ledger
  lock, but `engine.propose` never used `audit.transaction()` — concurrent
  proposes could each read `used < max` and collectively exceed the cap
  (TOCTOU). For a policy carrying a `rate_limit`, `propose` now runs the whole
  sequence inside the transaction lock, making the cap **exact among writers
  sharing one delego home on one host** (spec §5 consistency class; documented
  in SECURITY.md). Trade-off: the broker call holds the ledger lock for
  rate-limited policies — keep broker timeouts modest. Regression test:
  8 concurrent proposes against `max: 2` yield exactly 2 allows.

### Added
- **`delego verify` is honest about truncation (spec §8.3).** It now prints the
  chain head (`seq:entry_hash`) so it can be anchored externally, accepts
  `--expected-head SEQ:HASH` to check against an anchor, and — when no anchor
  is given — states that truncation of the most recent receipts cannot be
  ruled out instead of returning an unqualified "valid".
- `Policy.has_rate_limit` (used by the engine to scope the transaction lock).

## [0.2.4] — 2026-06-09

Packaging only; protocol unchanged (still 0.2). No functional, API, or
fingerprint changes.

### Added
- MCP Registry name marker (`mcp-name: io.github.Delego-Dev/delego`) in the
  README so delego can be published to the official MCP Registry
  (registry.modelcontextprotocol.io).

## [0.2.3] — 2026-06-08

Protocol unchanged (still 0.2). Security fixes; no fingerprint-preimage change.

### Security
- **Brokers now refuse an unauthorised query string (confused-deputy fix).**
  Through protocol 0.2 the action fingerprint covers method+host+path+params but
  **not** the URL query, so `/orders?to=me` and `/orders?to=attacker` share one
  fingerprint. The shipped brokers (`NullBroker`, `HTTPProxyBroker`, and the
  sample app's `HttpxBroker`) previously forwarded `action.url` verbatim,
  re-opening the gap. They now request `ProposedAction.fingerprinted_url`
  (scheme+host+path only) and **fail closed** (`BrokerRefusal`) on any
  query/fragment, per spec §4.2. New `ProposedAction.has_query` /
  `.fingerprinted_url` helpers.
- **Policy documents are validated and fail closed on load.** `Policy.load` now
  raises `PolicyError` on a structurally/semantically invalid policy and
  **rejects unknown `match`/`constraints`/top-level keys** (previously a
  misspelled constraint like `amount_max` was silently dropped — a fail-*open*
  hole that weakened a rule). Validated against a vendored copy of the spec's
  `schema/policy.json` when `jsonschema` is installed.
- **Rate limits hold under concurrency.** The evaluate→execute→append sequence
  for rate-limited rules is now serialized under the ledger lock, so concurrent
  proposes can no longer each observe `used < max` and collectively exceed the cap.

### Added
- Sample app: the human-approval endpoints (`/approvals/{id}/approve`, `/deny`)
  are gated behind a `DELEGO_APPROVAL_TOKEN` bearer (constant-time check), a
  **separate trust domain** from the agent-facing `/propose` & `/resolve`; they
  **fail closed** if the token is unset, so a compromised agent cannot approve
  its own actions.
- Exports: `PolicyError`, `BrokerRefusal`.

## [0.2.2] — 2026-06-04

Protocol unchanged (still 0.2).

### Security
- **Fail-open in the `amount` constraint fixed.** Amounts are now parsed as
  `Decimal` and **non-finite (`nan`/`inf`), negative, and non-numeric values are
  denied**. Previously `float('nan') > max` is `False`, so an `amount: "nan"`
  slipped past any cap. Also fixes float rounding on money comparisons.
- **Honest audit-tamper docs + a rollback hook.** `verify(expected_head=(seq, hash))`
  lets you anchor the ledger head externally to detect **tail truncation**, which
  hash-chaining alone can't (a truncated prefix verifies clean). README/SECURITY
  now state this and the local-signing-key limit plainly rather than overclaiming.

### Changed
- **`mcp` is now an optional extra.** `pip install delego` no longer pulls in
  `mcp` and its dependency tree (which can conflict with a system PyJWT); install
  the server with `pip install "delego[mcp]"`. Library/CLI users get a lean core.
- Ship a `py.typed` marker so downstream type checkers use delego's type hints.

### Added
- **`HTTPProxyBroker` is now a real adapter** (was a sketch): it forwards an
  authorised action — with its `intent_hash` and `action_fingerprint` for
  gateway-side re-verification — to an external credential gateway (OneCLI /
  vault / proxy) over stdlib HTTP, and returns the gateway's response. The
  upstream secret stays in the gateway; it never enters delego (`delego/brokers.py`,
  `tests/test_broker.py`).
- **`ROADMAP.md`** — a public, ordered plan (broker adapters → approval surfaces →
  signed authorization token → single-writer daemon) with "where to help".
- README **"Build on delego"** section linking the
  [sample app](https://github.com/Delego-Dev/sample-app) and the broker
  extension point.

## [0.2.1] — 2026-06-04

Protocol unchanged (still 0.2). Package versions are `0.x.y` where `x` is the
implemented protocol and `y` the iteration.

### Security
- **Concurrent-writer safety.** Appends to the signed audit ledger and the
  read-modify-write paths of the approval store (`create` / `decide` / `consume`)
  now take an exclusive OS file lock (`fcntl` on POSIX, `msvcrt` on Windows; no
  new dependency), so multiple agents writing to the same delego home can no
  longer fork the hash chain or interleave a torn record. This closes write
  *integrity* under concurrency; rate-limit *exactness* (the count→execute→append
  window) still requires the planned single-writer daemon.

### Added
- Concurrency regression tests: chain stays valid + contiguous under parallel
  appends; concurrent approval creates land intact; concurrent decisions converge
  to a single terminal status (`tests/test_concurrency.py`).

### Changed
- `__protocol_version__` is now the two-component `"0.2"` (protocol/spec versions
  are `0.x`; the package is `0.x.y`). README status/limitations updated.

## [0.2.0] — 2026-06-04

First public release on PyPI. (0.1.0 was the initial implementation and was never
published.) Implements wire-protocol **0.2**; see
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

[Unreleased]: https://github.com/Delego-Dev/delego/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/Delego-Dev/delego/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Delego-Dev/delego/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Delego-Dev/delego/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Delego-Dev/delego/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/Delego-Dev/delego/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Delego-Dev/delego/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Delego-Dev/delego/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Delego-Dev/delego/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Delego-Dev/delego/releases/tag/v0.2.0
