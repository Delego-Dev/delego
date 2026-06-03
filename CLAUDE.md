# CLAUDE.md — delego

Project context for Claude Code. Read this fully before changing anything.

## What delego is

delego is a **policy & audit firewall for agent actions**. It sits between an
agent and whatever credential broker holds the user's secrets, and it answers
the one question brokers don't: *is this specific action the thing the human
actually asked for?*

```
agent ──propose──▶ delego ──if allowed──▶ credential broker ──▶ service
(LLM)            (policy +              (OneCLI / Agent Vault /  (bank, SaaS,
                  approval +             Browser Use…)            API)
                  audit)
                    └── needs_approval ──▶ human (CLI)
```

Credential brokering (the agent never holds the secret) is a solved, crowded
space. The unsolved problem delego targets is the **confused deputy**: the agent
holds a *valid* credential, a prompt injection redirects it, the scope *covers*
the action, so a broker happily injects the secret. The credential is the wrong
layer to catch this — it's valid. delego authorises the *action*, deterministically,
before any credential is used, and leaves tamper-evident proof of why.

## Design invariants — DO NOT VIOLATE

These are the reason the tool exists. A "helpful" refactor that breaks one of
these breaks the product. If a task seems to require breaking one, stop and ask.

1. **No LLM in the authorization path.** Authorisation is pure, inspectable
   Python (`policy.py`, `engine.py`). A model may *advise* upstream, but the
   decision that gates a credential must be deterministic and reproducible.
2. **delego holds no credentials and makes no upstream request itself.** All
   execution is delegated through the `BrokerAdapter` interface. The secret must
   never enter delego's process or the agent's context.
3. **Fail closed.** Default is `deny`. A rule that matches but whose constraints
   fail becomes a `deny`, never a silent allow.
4. **Approvals are bound to the exact action fingerprint** (the confused-deputy
   guard in `engine.resolve`). An approval for action A must never release a
   different action B. Never loosen this check.
5. **The audit ledger is append-only, hash-chained, and Ed25519-signed.** Never
   rewrite history. If you change the receipt payload schema, you MUST update
   `_PAYLOAD_KEYS` and `verify()` together, and add a schema version — otherwise
   old chains stop verifying.
6. **Evaluation order is fixed:** forbidden (hard deny) → rules (first match
   wins) → default. Don't reorder or short-circuit it.

## Repo map

- `delego/models.py` — `ProposedAction` (derives `intent_hash` from the
  instruction, `fingerprint` from method+host+path+params) and `Decision`.
- `delego/policy.py` — the deterministic engine: load YAML, match rules, check
  constraints (`amount`, `allow_list`, `rate_limit`). **No LLM here.**
- `delego/audit.py` — tamper-evident receipt chain; `ensure_keys`, `append`,
  `verify`, `count_allows` (rate limiting reads the ledger).
- `delego/approval.py` — file-backed human approval queue (pending/approved/denied).
- `delego/brokers.py` — `BrokerAdapter` protocol; `NullBroker` (default, holds no
  creds, simulates execution) and `HTTPProxyBroker` (sketch, not wired).
- `delego/engine.py` — `Firewall.propose()` / `Firewall.resolve()`; the
  confused-deputy guard lives in `resolve`.
- `delego/config.py` — `Paths.resolve` (home precedence: `--home` → `DELEGO_HOME`
  → project-local `./.claude/.delego` if present → `~/.delego`), a `.gitignore`
  written into the home (keeps keys/ledger out of git), and `build_firewall()`
  (single wiring point for CLI + MCP).
- `delego/cli.py` — `delego` CLI: init, policy, pending, approve, deny, log, verify.
- `delego/mcp_server.py` — FastMCP server `delego_mcp` exposing
  `delego_propose_action`, `delego_resolve_action`, `delego_audit_tail`,
  `delego_show_policy`.
- `examples/demo.py` — end-to-end walkthrough; **this is the de facto spec.**
- `tests/` — pytest suite encoding the demo scenarios + invariant guards.
- `policy.example.yaml` — a BFSI-flavoured starter policy.

## Run & test

```bash
pip install -e ".[dev]"          # editable install + test deps; gives you the `delego` CLI
python examples/demo.py          # baseline: 8 scenarios + tamper detection, no agent needed
pytest                           # regression suite (encodes the eight demo scenarios)
delego init && delego verify     # CLI smoke test
```

The demo MUST show: allow, forbidden-deny, cap-exceeded-deny, needs_approval,
the confused-deputy guard refusing a substituted action, resolve-after-approval,
a valid chain, and tamper detection after editing a receipt. If any of those
change, you've regressed a core behaviour.

**MCP dependency gotcha:** installing `mcp` can conflict with a system-installed
`PyJWT` (`pip install mcp` may fail to uninstall it). Use a venv for the MCP
extra: `python -m venv .venv && .venv/bin/pip install -e . mcp`. Validate with:

```python
import asyncio, delego.mcp_server as m
print(m.mcp.name); print([t.name for t in asyncio.run(m.mcp.list_tools())])
```

The regression suite in `tests/` encodes the demo scenarios (plus invariant
guards); `.github/workflows/ci.yml` runs both the suite and the demo on Python
3.10–3.12.

## Conventions

- Python ≥ 3.10. Core models use dataclasses (keep runtime deps light and
  auditable — this is a security tool). Pydantic only at the MCP boundary.
- FastMCP tools: name `delego_<verb>`, always set `annotations`
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`) and
  write a docstring that documents the JSON return shape.
- Keep dependencies minimal and pinned-ish; justify any new one.
- License: Apache-2.0. Never commit keys or ledger files (see `.gitignore`).
- Update `README.md` and the tests alongside any behaviour change.

## Roadmap (ordered)

1. **Tests + CI.** ✅ Done — `tests/` encodes the eight demo scenarios (plus
   invariant guards) and `.github/workflows/ci.yml` runs the suite and the demo
   on Python 3.10–3.12.
2. **OneCLI broker adapter.** Implement a real `BrokerAdapter` that forwards the
   already-authorised request through OneCLI's local gateway (it injects the
   credential and forwards upstream). Add a matching policy example and a short
   doc. Do not change the decision/audit core to do this.
3. **Browser Use adapter.** A second adapter for JS-heavy UI-only apps.
4. **FastAPI daemon.** A long-running daemon so non-MCP clients work and the CLI
   and MCP server share live state over a socket instead of files.
5. **Signed authorization token (v0.3, the real moat).** When delego allows or
   approves an action, mint a short-lived token bound to the action fingerprint
   + intent hash. The broker requires and verifies it before injecting — closing
   the gap where a broker would inject for *any* in-scope request. Look at
   RFC 8693 (token exchange / downscoping) as prior art.
6. Richer path matching (real per-segment globbing; today `**` and `*` collapse).
7. Package and publish to PyPI as `delego`.

## Working agreement

- Propose a short plan before any change that touches more than one module or
  any invariant-adjacent code; wait for confirmation.
- Make small, reviewable commits with clear messages.
- After any change, re-run `python examples/demo.py` and the test suite and
  report the results.
