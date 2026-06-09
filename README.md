# delego

<!-- mcp-name: io.github.Delego-Dev/delego -->

[![CI](https://github.com/Delego-Dev/delego/actions/workflows/ci.yml/badge.svg)](https://github.com/Delego-Dev/delego/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**Intent-bound action authorization for AI agents.** It sits between an agent and
whatever credential broker holds the user's secrets, and it answers the one
question brokers don't: *is this specific action the thing the human actually
asked for?*

```
   agent  ──propose──▶  delego  ──if allowed──▶  credential broker  ──▶  service
   (LLM)               (policy +                (Agent Vault /         (bank,
                        approval +               OneCLI /               SaaS,
                        audit)                   Browser Use…)          API)
                           │
                           └── needs_approval ──▶  human (CLI)
```

📜 **Protocol:** delego implements **protocol 0.2** of the open [delego wire specification](https://github.com/Delego-Dev/specification) — canonicalization, the policy schema, intent/fingerprint binding, and the signed audit chain. The authorization token (spec 0.3) is specified but not yet implemented.

## Why this exists

The "agent gets its own scoped credential, and never holds the user's secret
directly" pattern is now a crowded, converging space — Infisical's **Agent
Vault**, **OneCLI**, **Browser Use**, **Nango**, and others all do credential
brokering.

The harder problem sits one level up — the **confused deputy**: the agent holds
a *valid* credential, a prompt injection redirects it, the scope *covers* the
action, so the broker happily injects the secret and the action goes through.
The credential is the wrong place to catch this — it's valid. OAuth tokens carry
no commitment to the original instruction.

Authorising the *action* (not just the credential) is an active area — see
deterministic policy engines (OPA/Cedar, Permit), human-in-the-loop approval
(HumanLayer), MCP gateways/firewalls, and the "pre-action authorization" line of
research. delego is a small, **deterministic, local, Apache-2.0 reference** for
it: no LLM in the decision path, no credential custody, approvals bound to the
exact action fingerprint, and a signed, hash-chained audit trail — riding the
existing broker layer rather than competing with it.

## What it is / isn't

- **Is** a decision-and-audit layer. Deterministic policy, human approval for
  sensitive actions, signed append-only audit ledger.
- **Isn't** a credential vault or a proxy. It delegates execution to a broker
  through a thin `BrokerAdapter` interface — you ride the existing layer instead
  of rebuilding it.
- **Authorisation is pure Python, no LLM in the loop.** A model can advise
  upstream; the decision that gates a credential is made outside the stochastic
  loop, so an injection can't talk its way past it.

## Key properties

1. **Intent binding** — every action carries a hash of the original human
   instruction, recorded in the audit ledger and re-checked at resolve time, so
   an approval cannot be re-pointed at a different claimed instruction.
2. **Action-bound, single-use approval** — a human "yes" is bound to one exact
   action fingerprint. An agent that gets approval for action A cannot reuse it
   to run action B (the confused-deputy guard), and cannot replay the *same*
   approval to run action A twice — an approval releases its action exactly once.
3. **Tamper-evident audit** — receipts form an Ed25519-signed hash chain.
   Editing, reordering, removing a receipt, or dropping a field breaks
   verification, which reports the fault rather than trusting the ledger.
   *Caveats (be precise):* hash-chaining does **not** catch truncation of the
   most recent receipts (a tail-truncated prefix verifies clean), and the local
   signing key protects nothing against a host compromise. For rollback
   detection, anchor the head externally and pass it to `verify(expected_head=…)`;
   for key safety, use an HSM/KMS. See [SECURITY.md](SECURITY.md).

## Quickstart

```bash
pip install delego          # the `delego` library + CLI
# pip install "delego[mcp]" # add the `delego-mcp` server (MCP is an optional extra)
delego init               # creates ~/.delego with signing keys and an example policy
delego policy             # inspect the active policy
```

To run the full loop end-to-end from a clone — an allowed read, a forbidden deny,
an over-cap deny, an approval flow, the confused-deputy guard refusing a
substituted action, and audit-chain tamper detection (no agent or live service
needed):

```bash
git clone https://github.com/Delego-Dev/delego && cd delego
pip install -e ".[dev]"
python examples/demo.py
pytest
```

### Human side (CLI)

```bash
delego policy            # show the active policy
delego pending           # list actions awaiting approval
delego approve apr_xxxx  # release a parked action (or: delego deny apr_xxxx)
delego log -n 20         # read recent receipts
delego verify            # check the audit chain (hashes, linkage, signatures)
```

### Agent side (MCP) — wiring into Claude Code

delego ships an MCP server (`delego_mcp`) over stdio — install it with the `mcp`
extra: `pip install "delego[mcp]"`. Register it in your MCP
config (for Claude Code, `.mcp.json` at the project root) so the agent can
propose actions. Set `DELEGO_HOME` to keep the policy, signing keys, and ledger
project-scoped under `.claude/.delego`:

```json
{
  "mcpServers": {
    "delego": {
      "command": "delego-mcp",
      "env": { "DELEGO_HOME": "/abs/path/to/project/.claude/.delego" }
    }
  }
}
```

Initialise that home and approve from the same one (the CLI and MCP server must
share a home):

```bash
delego --home .claude/.delego init       # keys, example policy, and a .gitignore
delego --home .claude/.delego pending    # ...then: delego --home .claude/.delego approve apr_xxxx
```

If `DELEGO_HOME` is unset, the CLI also auto-uses `./.claude/.delego` when run
from the project root, falling back to `~/.delego`. (Use an absolute path in the
MCP `env`, since the server's launch directory isn't guaranteed.)

Tools exposed:

| tool | what it does |
|------|--------------|
| `delego_propose_action` | submit an action; returns allow / deny / needs_approval |
| `delego_resolve_action` | complete an approved action (fingerprint must match) |
| `delego_audit_tail` | read recent receipts |
| `delego_show_policy` | show the active policy |

Typical flow: the agent calls `delego_propose_action`. If it comes back
`needs_approval` with an `approval_id`, a human runs `delego approve <id>`, then
the agent calls `delego_resolve_action` with the identical action to complete it.

## Policy format

A rule matches on `method` / `host` / `path` (glob) / `path_contains`, decides
`allow` or `needs_approval`, and can attach constraints. Order is forbidden
(hard deny) → rules (first match wins) → `default`. A matched rule whose
constraints fail becomes a deny (fail-closed). See `policy.example.yaml`.

```yaml
rules:
  - name: place-order
    decision: needs_approval
    match: { method: POST, host: api.example.com, path: /orders }
    constraints:
      amount:     { field: amount, max: 5000, currency: USD }
      allow_list: { field: destination, in: [internal] }
```

Supported constraints: `amount` (cap + currency), `allow_list`
(field-in-set), `rate_limit` (max per minute/hour/day, counted from the ledger).

## Build on delego

Three ways to use it, lowest friction first:

- **As an MCP server** — `delego init`, add the `delego-mcp` server to your MCP
  config, and your agent proposes actions instead of executing them. No code.
- **As a library** — `pip install delego`, write a policy + a `BrokerAdapter`, and
  call `fw.propose(...)` in your tool-call path.
- **Behind a service** — wrap the `Firewall` in an HTTP API so many agents share
  one decision point and one audit chain.

The one extension point is the **broker** — where your credential lives and the
authorised action actually runs. delego never holds the secret:

- `NullBroker` (default) — simulates execution; for demos and tests.
- `HTTPProxyBroker(gateway_url)` — forwards the authorised action to an external
  credential gateway (OneCLI / vault / proxy) that injects the secret upstream.
- Your own — implement `execute(action) -> dict` against the `BrokerAdapter`
  protocol in [`delego/brokers.py`](delego/brokers.py).

▶ **[Delego-Dev/sample-app](https://github.com/Delego-Dev/sample-app)** — a
FastAPI service built on the published package, with the full
propose → approve → resolve loop and a copy-paste curl walkthrough. The best
starting point for building your own.

See **[ROADMAP.md](ROADMAP.md)** for where delego is going and where to help.

## Status

- **Implemented (protocol 0.2):** the policy engine, intent hashing, action
  fingerprinting, the confused-deputy guard, intent-bound + single-use human
  approvals, and the signed, hash-chained audit ledger with verification.
- **Brokers:** the default `NullBroker` holds no credentials and makes no real
  request — it records what *would* be sent (for demos and tests). `HTTPProxyBroker`
  forwards an authorised action to an external credential gateway; or write your
  own against the `BrokerAdapter` protocol in `delego/brokers.py`.
- **Not yet:** the authorization token (spec 0.3), an always-on daemon (state is
  file-backed and shared by the CLI and MCP server), and a non-MCP HTTP surface.
- **Known limitations:** concurrent writes to the file-backed ledger and approval
  store are serialised with an OS file lock (corruption-safe), but rate-limit
  *exactness* under concurrency still needs the planned single-writer daemon;
  path globbing is coarse (`**` and `*` collapse); the URL query string is not
  part of the action fingerprint (spec 0.3).

## License

Licensed under the [Apache License 2.0](LICENSE).
