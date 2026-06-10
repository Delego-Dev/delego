"""``delego`` command-line interface.

Covers the human side of the loop: initialise state and keys, inspect the
policy, review and decide pending approvals, and read/verify the audit ledger.
The agent side goes through the MCP server (``delego.mcp_server``).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import click

from .audit import AuditLog, ensure_keys
from .client import DaemonClient, daemon_running
from .config import Paths, ensure_home_gitignore
from .policy import Policy

_EXAMPLE_POLICY = Path(__file__).resolve().parent.parent / "policy.example.yaml"


def _daemon(paths: Paths) -> DaemonClient | None:
    """Return a client to a live daemon at this home, else None.

    When a daemon owns the home it is the sole writer; the CLI routes through it
    so a human approve/deny doesn't fork state behind the daemon's back."""
    return DaemonClient(paths.socket) if daemon_running(paths.socket) else None


@click.group()
@click.option("--home", default=None, help="Delego home dir (default: $DELEGO_HOME or ~/.delego)")
@click.pass_context
def cli(ctx: click.Context, home: str | None) -> None:
    """Delego — a policy & audit firewall for agent actions."""
    ctx.obj = Paths.resolve(home)


@cli.command()
@click.pass_obj
def init(paths: Paths) -> None:
    """Create the home dir, generate signing keys, install an example policy."""
    paths.home.mkdir(parents=True, exist_ok=True)
    ensure_home_gitignore(paths.home)
    ensure_keys(paths.private_key, paths.public_key)
    if not paths.policy.exists():
        if _EXAMPLE_POLICY.exists():
            shutil.copy(_EXAMPLE_POLICY, paths.policy)
            click.echo(f"Installed example policy at {paths.policy}")
        else:
            click.echo("No example policy found; create policy.yaml yourself.")
    click.echo(f"Initialised delego home at {paths.home}")
    click.echo(f"Signing key: {paths.private_key}")


@cli.command()
@click.pass_obj
def home(paths: Paths) -> None:
    """Print the resolved delego home (where state + policy live)."""
    click.echo(str(paths.home))


@cli.command()
@click.option("--mint-tokens", is_flag=True, help="Mint §9 authorization tokens on allow (separate token key).")
@click.option("--audience", default="broker:default", help="Token audience identifier (with --mint-tokens).")
@click.pass_obj
def daemon(paths: Paths, mint_tokens: bool, audience: str) -> None:
    """Run the single-writer daemon: one process owns the ledger.

    Every client (the CLI's approve/deny, and agents) then routes through it, so
    `rate_limit` is exact across all of them and the chain has one writer. Runs
    until Ctrl-C / SIGTERM. Run a single daemon per home.
    """
    from .daemon import serve

    click.echo(f"delego daemon — home {paths.home}")
    click.echo(f"listening on {paths.socket} (Ctrl-C to stop)")
    serve(paths, mint_tokens=mint_tokens, token_audience=audience)


@cli.command()
@click.pass_obj
def policy(paths: Paths) -> None:
    """Show the loaded policy summary."""
    click.echo(f"home:   {paths.home}")
    p = Policy.load(paths.policy)
    click.echo(f"policy v{p.version} | default: {p.default}")
    click.echo("\nforbidden:")
    for r in p.forbidden:
        click.echo(f"  - {r.name}: {r.match}")
    click.echo("\nrules:")
    for r in p.rules:
        line = f"  - {r.name} -> {r.decision} | {r.match}"
        if r.constraints:
            line += f" | constraints: {r.constraints}"
        click.echo(line)


@cli.command()
@click.pass_obj
def pending(paths: Paths) -> None:
    """List actions awaiting human approval."""
    d = _daemon(paths)
    if d is not None:
        items = d.pending()
    else:
        from .approval import ApprovalStore

        items = ApprovalStore(paths.approvals).pending()
    if not items:
        click.echo("No pending approvals.")
        return
    for rec in items:
        click.echo(f"{rec['id']}  {rec['summary']}")
        if rec.get("instruction"):
            click.echo(f"    instruction: {rec['instruction']!r}")
        click.echo(f"    requested {rec['created_at']}")


@cli.command()
@click.argument("approval_id")
@click.option("--as", "approver", default="cli", help="Name recorded as approver")
@click.pass_obj
def approve(paths: Paths, approval_id: str, approver: str) -> None:
    """Approve a pending action."""
    _decide(paths, approval_id, True, approver)


@cli.command()
@click.argument("approval_id")
@click.option("--as", "approver", default="cli", help="Name recorded as approver")
@click.pass_obj
def deny(paths: Paths, approval_id: str, approver: str) -> None:
    """Deny a pending action."""
    _decide(paths, approval_id, False, approver)


def _decide(paths: Paths, approval_id: str, approved: bool, approver: str) -> None:
    # Route writes through a live daemon (the sole writer) so a human decision
    # never forks state behind it; otherwise decide directly on the store.
    d = _daemon(paths)
    if d is not None:
        rec = d.decide(approval_id, approved, approver)
    else:
        from .approval import ApprovalStore

        rec = ApprovalStore(paths.approvals).decide(approval_id, approved, approver)
    if rec is None:
        click.echo(f"No such approval: {approval_id}")
        raise SystemExit(1)
    # Echo exactly what was decided: this is the human consent moment, and the
    # approver should see the action and instruction, not just an opaque id.
    click.echo(f"{approval_id}: {rec['status']}")
    click.echo(f"    {rec['summary']}")
    if rec.get("instruction"):
        click.echo(f"    instruction: {rec['instruction']!r}")


@cli.command()
@click.option("-n", "--lines", default=20, help="Number of receipts to show")
@click.pass_obj
def log(paths: Paths, lines: int) -> None:
    """Show the most recent audit receipts."""
    audit = AuditLog(paths.audit_log, paths.private_key, paths.public_key)
    for e in audit.tail(lines):
        click.echo(
            f"#{e['seq']} [{e['phase']}/{e['outcome']}] {e['action_summary']}"
            + (f"  rule={e['rule']}" if e["rule"] else "")
        )
        for r in e["reasons"]:
            click.echo(f"      - {r}")


@cli.command()
@click.option(
    "--expected-head",
    default=None,
    metavar="SEQ:ENTRY_HASH",
    help="External head anchor to check the chain against (spec §8.3). "
    "Persist the seq + entry_hash printed by this command somewhere the "
    "ledger's writer cannot rewrite, and pass it back here to detect "
    "truncation/rollback.",
)
@click.option(
    "--anchor-file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Path to a head-anchor file: verification checks the chain against "
    "the head stored there (if any) and, on success, updates it to the "
    "current head. Keep the file somewhere the ledger's writer cannot "
    "rewrite (another volume, another host).",
)
@click.pass_obj
def verify(paths: Paths, expected_head: str | None, anchor_file: str | None) -> None:
    """Verify the audit chain (hashes, linkage, signatures)."""
    if expected_head is not None and anchor_file is not None:
        raise click.UsageError("use either --expected-head or --anchor-file, not both")
    click.echo(f"home: {paths.home}")
    audit = AuditLog(paths.audit_log, paths.private_key, paths.public_key)
    anchor_path = Path(anchor_file) if anchor_file is not None else None

    head = None
    if anchor_path is not None and anchor_path.exists():
        expected_head = anchor_path.read_text(encoding="utf-8").strip()
    if expected_head is not None:
        seq_s, _, hash_s = expected_head.partition(":")
        if not seq_s.isdigit() or not hash_s:
            raise click.BadParameter("expected SEQ:ENTRY_HASH, e.g. 41:9f3c…", param_hint="--expected-head")
        head = (int(seq_s), hash_s)

    ok, problems = audit.verify(expected_head=head)
    if not ok:
        click.echo("AUDIT CHAIN FAILED:")
        for p in problems:
            click.echo(f"  - {p}")
        raise SystemExit(1)

    click.echo("Audit chain OK: all receipts intact and signed.")
    last = audit.tail(1)
    current = f"{last[-1]['seq']}:{last[-1]['entry_hash']}" if last else None
    if current:
        click.echo(f"head: {current}")
    if head is not None:
        click.echo("Head anchor matches: no truncation/rollback against the anchor.")
    if anchor_path is not None and current:
        # Advance the anchor only after a clean verify, so it always names a
        # head this auditor actually checked.
        anchor_path.write_text(current + "\n", encoding="utf-8")
        click.echo(f"Anchor updated: {anchor_file}")
    elif head is None:
        # Spec §8.3: an auditor holding no external anchor must not return
        # an unqualified "valid" — a tail-truncated ledger verifies clean.
        click.echo(
            "Note: without an external head anchor, truncation of the most "
            "recent receipts cannot be ruled out. Persist the head printed "
            "above outside this machine and verify with --expected-head or "
            "--anchor-file."
        )


if __name__ == "__main__":
    cli()
