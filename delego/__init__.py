"""delego — a policy & audit firewall for agent actions.

This package authorises an *action* (deterministically, no LLM in the loop)
before any credential is used, parks sensitive actions for human approval, and
writes a tamper-evident signed audit chain. See ``CLAUDE.md`` for the design
invariants and ``examples/demo.py`` for the de facto spec.

The names below are the public API: the CLI (``delego.cli``) and MCP server
(``delego.mcp_server``) are entry points, everything else an integrator needs is
re-exported here. This module is re-export only — no logic lives here.
"""

from __future__ import annotations

from .audit import AuditLog, ensure_keys
from .config import Paths, build_firewall
from .engine import Firewall
from .models import (
    OUTCOME_ALLOW,
    OUTCOME_APPROVAL,
    OUTCOME_DENY,
    Decision,
    ProposedAction,
)
from .policy import Policy

__version__ = "0.1.0"  # package (PyPI) version

# Highest delego *protocol* version (see the wire spec's "Protocol versions")
# this reference implements. The spec leads the reference: the spec's version
# MUST always be >= this. Distinct from __version__, the package release version.
__protocol_version__ = "0.2.0"

__all__ = [
    "ProposedAction",
    "Decision",
    "Firewall",
    "Policy",
    "AuditLog",
    "ensure_keys",
    "Paths",
    "build_firewall",
    "OUTCOME_ALLOW",
    "OUTCOME_DENY",
    "OUTCOME_APPROVAL",
    "__version__",
    "__protocol_version__",
]
