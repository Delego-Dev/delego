# delego

[![CI](https://github.com/Delego-Dev/delego/actions/workflows/ci.yml/badge.svg)](https://github.com/Delego-Dev/delego/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

A **policy & audit firewall for agent actions**. It sits between an agent and
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
   instruction, recorded in the audit ledger.
2. **Action-bound approval** — a human "yes" is bound to one exact action
   fingerprint. An agent that gets approval for action A cannot reuse it to run
   action B (the confused-deputy guard).
3. **Tamper-evident audit** — receipts form an Ed25519-signed hash chain.
   Editing or deleting any past receipt breaks verification.

## Quickstart

```bash
pip install delego        # installs the `delego` CLI and the `delego-mcp` server
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

delego ships an MCP server (`delego_mcp`) over stdio. Register it in your MCP
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
  - name: small-domestic-transfer
    decision: needs_approval
    match: { method: POST, host: api.examplebank.in, path: /transfer }
    constraints:
      amount:     { field: amount, max: 5000, currency: INR }
      allow_list: { field: beneficiary_type, in: [domestic] }
```

Supported constraints in v0.1: `amount` (cap + currency), `allow_list`
(field-in-set), `rate_limit` (max per minute/hour/day, counted from the ledger).

## Status (v0.1)

- **Implemented:** the policy engine, intent hashing, action fingerprinting, the
  confused-deputy guard, the human approval queue, and the signed, hash-chained
  audit ledger with verification.
- **Stubbed:** the broker. The default `NullBroker` holds no credentials and
  makes no real request — it records what *would* be sent. Swap in a real
  `BrokerAdapter` (see the `HTTPProxyBroker` sketch in `delego/brokers.py`) to act
  on live services.
- **Not yet:** an always-on daemon (v0.1 uses file-backed state shared by the CLI
  and MCP server) and a non-MCP HTTP surface.
- **Known limitations:** file-backed state is not safe under concurrent writers
  (a single-writer daemon is planned); path globbing is coarse (`**` and `*`
  collapse).

## License

Licensed under the [Apache License 2.0](LICENSE).
