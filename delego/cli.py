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
from .config import Paths, ensure_home_gitignore
from .policy import Policy

_EXAMPLE_POLICY = Path(__file__).resolve().parent.parent / "policy.example.yaml"


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
    from .approval import ApprovalStore

    rec = ApprovalStore(paths.approvals).decide(approval_id, approved, approver)
    if rec is None:
        click.echo(f"No such approval: {approval_id}")
        raise SystemExit(1)
    click.echo(f"{approval_id}: {rec['status']}")


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
@click.pass_obj
def verify(paths: Paths) -> None:
    """Verify the audit chain (hashes, linkage, signatures)."""
    click.echo(f"home: {paths.home}")
    audit = AuditLog(paths.audit_log, paths.private_key, paths.public_key)
    ok, problems = audit.verify()
    if ok:
        click.echo("Audit chain OK: all receipts intact and signed.")
    else:
        click.echo("AUDIT CHAIN FAILED:")
        for p in problems:
            click.echo(f"  - {p}")
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
