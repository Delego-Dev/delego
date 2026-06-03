"""Where state lives on disk, and how to assemble a ``Firewall`` from it.

The delego home directory holds the signing keys, the policy, the audit ledger,
and the approval queue. ``build_firewall`` is the single wiring point used by
both the CLI and the MCP server, so they operate on the same state.

Home resolution (see ``Paths.resolve``) lets state be per-user (``~/.delego``)
or project-scoped and co-located with Claude Code config (``.claude/.delego``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .approval import ApprovalStore
from .audit import AuditLog, ensure_keys
from .brokers import BrokerAdapter
from .engine import Firewall
from .policy import Policy

# State that must never be committed when the home lives inside a repo
# (e.g. ``.claude/.delego``). ``policy.yaml`` is intentionally left trackable so
# a team can version and share the policy; secrets and the ledger are not.
_STATE_GITIGNORE = """\
# delego runtime state — do not commit secrets or the audit ledger.
signing_key.pem
audit.log.jsonl
approvals.jsonl
*.lock
"""


@dataclass
class Paths:
    home: Path

    @classmethod
    def resolve(cls, home: str | os.PathLike | None = None) -> "Paths":
        """Resolve the delego home, in precedence order:

        1. an explicit ``home`` argument (the CLI ``--home`` flag);
        2. the ``DELEGO_HOME`` environment variable;
        3. a project-local ``./.claude/.delego`` directory **if it already
           exists** — only the current directory is checked, never a parent, so
           the home can't be silently picked up from an ancestor;
        4. the per-user default ``~/.delego``.

        The MCP server and CLI both resolve through here. Set ``DELEGO_HOME``
        (the MCP config does) to pin the home explicitly and not depend on the
        working directory.
        """
        if home is not None:
            return cls(home=Path(home))

        env = os.environ.get("DELEGO_HOME")
        if env:
            return cls(home=Path(env))

        project_local = Path.cwd() / ".claude" / ".delego"
        if project_local.is_dir():
            return cls(home=project_local)

        return cls(home=Path.home() / ".delego")

    @property
    def private_key(self) -> Path:
        return self.home / "signing_key.pem"

    @property
    def public_key(self) -> Path:
        return self.home / "signing_key.pub"

    @property
    def audit_log(self) -> Path:
        return self.home / "audit.log.jsonl"

    @property
    def approvals(self) -> Path:
        return self.home / "approvals.jsonl"

    @property
    def policy(self) -> Path:
        return self.home / "policy.yaml"


def ensure_home_gitignore(home: str | os.PathLike) -> None:
    """Drop a ``.gitignore`` in the home so keys/ledger aren't committed when the
    home lives inside a repo (e.g. ``.claude/.delego``). No-op if one exists."""
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    gitignore = home / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(_STATE_GITIGNORE, encoding="utf-8")


def build_firewall(paths: Paths, broker: BrokerAdapter | None = None) -> Firewall:
    # Load policy first: a missing/invalid policy fails closed with a clear
    # message before any state (keys, ledger) is created.
    policy = Policy.load(paths.policy)
    ensure_home_gitignore(paths.home)
    ensure_keys(paths.private_key, paths.public_key)
    audit = AuditLog(paths.audit_log, paths.private_key, paths.public_key)
    approvals = ApprovalStore(paths.approvals)
    return Firewall(policy, audit, approvals, broker=broker)
