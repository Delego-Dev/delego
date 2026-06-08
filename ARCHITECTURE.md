# Architecture

How delego is put together, and the invariants that define it. For the rules on
*contributing* changes (including the design invariants you must not break), see
[CONTRIBUTING.md](CONTRIBUTING.md). The wire protocol is specified separately at
[Delego-Dev/specification](https://github.com/Delego-Dev/specification), which
**leads** this reference (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## What delego is

delego is **intent-bound action authorization for AI agents**. It sits between an
agent and whatever credential broker holds the user's secrets, and answers the
question brokers don't: *is this specific action the thing the human actually
asked for?*

```
agent ──propose──▶ delego ──if allowed──▶ credential broker ──▶ service
(LLM)            (policy +              (holds the secret,      (bank, SaaS,
                  approval +             injects it, forwards)    API)
                  audit)
                    └── needs_approval ──▶ human (CLI)
```

Credential brokering (the agent never holds the secret) is a crowded, converging
space. The harder problem delego targets is the **confused deputy**: the agent
holds a *valid* credential, a prompt injection redirects it, the scope *covers*
the action, so a broker happily injects the secret. The credential is the wrong
layer to catch this — it's valid. delego authorises the *action*,
deterministically, before any credential is used, and leaves tamper-evident proof
of why.

## Design invariants

These are the reason the tool exists; a change that breaks one breaks the
product. They are enumerated, with the "do not violate" framing, in
[CONTRIBUTING.md](CONTRIBUTING.md):

1. **No LLM in the authorization path** (`policy.py`, `engine.py`).
2. **delego holds no credentials** and makes no upstream request itself.
3. **Fail closed** — default `deny`; a matched-but-failed constraint is a deny.
4. **Approvals are bound to the exact action fingerprint *and* intent, and are
   single-use** (the confused-deputy guard in `engine.resolve`).
5. **The audit ledger is append-only, hash-chained, and Ed25519-signed.**
6. **Evaluation order is fixed:** forbidden → rules (first match wins) → default.

## Evaluation order

`policy.evaluate` is the deterministic core:

1. **`forbidden`** — hard blocks, always deny, checked first.
2. **`rules`** — first matching rule decides (`allow` / `needs_approval`),
   subject to its constraints. A matched rule whose constraints fail becomes a
   deny (fail-closed).
3. **`default`** — used when nothing matched (recommended: `deny`).

## Repo map

- `delego/models.py` — `ProposedAction` (derives `intent_hash` from the
  instruction, `fingerprint` from method+host+path+params) and `Decision`.
- `delego/policy.py` — the deterministic engine: load YAML, match rules, check
  constraints (`amount`, `allow_list`, `rate_limit`). **No LLM here.**
- `delego/audit.py` — tamper-evident receipt chain; `ensure_keys`, `append`,
  `verify`, `count_allows` (rate limiting reads the ledger).
- `delego/_locking.py` — a cross-process file lock (`fcntl` / `msvcrt`) that
  serialises ledger appends and approval read-modify-writes, so concurrent
  writers to one home can't fork the chain or tear a record.
- `delego/approval.py` — file-backed human approval queue
  (pending/approved/denied/consumed).
- `delego/brokers.py` — `BrokerAdapter` protocol; `NullBroker` (default, holds no
  creds, simulates execution) and `HTTPProxyBroker` (forwards an authorised action
  to an external credential gateway that injects the secret).
- `delego/engine.py` — `Firewall.propose()` / `Firewall.resolve()`; the
  confused-deputy guard lives in `resolve`.
- `delego/config.py` — `Paths.resolve` (home precedence), the `.gitignore`
  written into the home, and `build_firewall()` (single wiring point for CLI +
  MCP; loads the policy first so a missing/invalid policy fails closed).
- `delego/cli.py` — the `delego` CLI: init, home, policy, pending, approve, deny,
  log, verify.
- `delego/mcp_server.py` — FastMCP server exposing `delego_propose_action`,
  `delego_resolve_action`, `delego_audit_tail`, `delego_show_policy`.
- `examples/demo.py` — end-to-end walkthrough; the de facto behavioural spec.
- `tests/` — pytest suite (the demo scenarios + invariant guards).
- `policy.example.yaml` — a generic starter policy for an HTTP/JSON API.

## Conventions

- Python ≥ 3.10. Core models use dataclasses (keep runtime deps light and
  auditable — this is a security tool). Pydantic only at the MCP boundary.
- FastMCP tools: name `delego_<verb>`, always set `annotations`
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`) and
  document the JSON return shape in the docstring.
- Keep dependencies minimal and pinned-ish; justify any new one.
- `__protocol_version__` is the highest wire-protocol version this reference
  implements; it MUST stay ≤ the spec's version.
