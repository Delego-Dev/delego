# Roadmap

Where delego is going and **where to help**. delego is intent-bound action
authorization for AI agents; the core (deterministic decisions + a signed audit chain) is
shipped and stable. The work below is ordered by what unblocks real adoption.

Versioning: the **protocol/spec** is `0.x` (the [wire spec](https://github.com/Delego-Dev/specification)
leads the code); the **PyPI package** is `0.x.y` where `x` is the protocol it
implements and `y` the iteration. Normative changes land in the spec first.

## Shipped

- **Deterministic policy engine** — `forbidden → rules → default deny`, fail-closed.
- **Intent + action-fingerprint binding**; **intent-bound, single-use** human
  approvals (the confused-deputy guard).
- **Append-only, Ed25519-signed, hash-chained audit ledger** with verification.
- **CLI** and an **MCP server** (`delego_propose_action` / `_resolve_action` /
  `_pending` / `_audit_tail` / `_show_policy`; approve/deny stay off the MCP
  surface by design).
- **Concurrency-safe** file-backed state (0.2.1 lock).
- **`HTTPProxyBroker`** — forwards an authorised action to an external credential
  gateway (0.2.2).
- Published on **PyPI** (`pip install delego`); a **[sample app](https://github.com/Delego-Dev/sample-app)**
  (FastAPI) shows how to build on it.
- **Query-string-bound fingerprint** (spec §4.2) — the URL query is folded into
  the `action_fingerprint`, so decision-relevant data can't ride it (0.3.0,
  breaking; regenerated CTK vectors). Rate-limited proposes are serialized under
  the ledger lock, making the cap exact on a single host (0.3.0).

## Now — make it usable in production (protocol 0.3)

1. **More broker adapters.** The broker is where a real credential lives; delego
   never holds it. `HTTPProxyBroker` (gateway-forwarding) ships in 0.2.2.
   - A **OneCLI** adapter (forward through OneCLI's local gateway).
   - A **Browser Use** adapter for JS-heavy UI-only apps.
   - *Where to help:* write an adapter for your vault/proxy against the
     `BrokerAdapter` protocol in `delego/brokers.py`; it must not change the
     decision/audit core.
2. **Human-approval surfaces beyond the CLI.** Nobody approves production actions
   in a terminal. Slack / webhook / dashboard approval flows on top of the
   approval queue.
   - *Where to help:* the [sample app](https://github.com/Delego-Dev/sample-app)
     is the home for these — a Slack interactive-button approver is next.
3. **Integration docs.** A "drop delego into your agent in 10 minutes" guide and a
   policy cookbook.

## Next — differentiate and harden (protocol 0.3, spec-first)

4. **Signed authorization token** (spec §9, already drafted). On allow/approve,
   mint a short-lived JWS bound to the action fingerprint + intent; a broker
   verifies it before injecting a credential. Closes the gap where a broker would
   inject for *any* in-scope request, and makes delego composable across vendors.
   *This is the moat.*
5. **Single-writer daemon.** A long-running process so non-MCP clients work, the
   CLI + MCP share live state over a socket, and rate-limit counting is exact
   across hosts without holding a file lock through broker calls (0.2.1 made
   writes corruption-safe; 0.3.0 made the cap exact on one host; this makes it
   serial everywhere).

## Later

7. Richer path matching (real per-segment globbing; today `**` and `*` collapse).
8. Policy ergonomics (templates, dry-run/"explain", testing helpers).

## How to contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [ARCHITECTURE.md](ARCHITECTURE.md)
first — especially the **invariants that must not be broken**. Normative protocol
changes go to the [specification](https://github.com/Delego-Dev/specification)
repo first (spec + CTK vectors), then the reference follows. Pick an item above,
open an issue to claim it, and send a PR from a fork.
