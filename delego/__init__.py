"""delego — a policy & audit firewall for agent actions.

This package authorises an *action* (deterministically, no LLM in the loop)
before any credential is used, parks sensitive actions for human approval, and
writes a tamper-evident signed audit chain. See ``ARCHITECTURE.md`` for the design
invariants and ``examples/demo.py`` for the de facto spec.

The names below are the public API: the CLI (``delego.cli``) and MCP server
(``delego.mcp_server``) are entry points, everything else an integrator needs is
re-exported here. This module is re-export only — no logic lives here.
"""

from __future__ import annotations

from .audit import AuditLog, ensure_keys
from .brokers import BrokerRefusal
from .config import Paths, build_firewall
from .engine import Firewall
from .models import (
    OUTCOME_ALLOW,
    OUTCOME_APPROVAL,
    OUTCOME_DENY,
    Decision,
    ProposedAction,
)
from .policy import Policy, PolicyError

__version__ = "0.2.3"  # PyPI package version, 0.x.y (x = protocol, y = iteration)

# Highest delego *protocol* version (see the wire spec's "Protocol versions")
# this reference implements. Protocol/spec versions are 0.x (two-component); the
# PyPI package is 0.x.y where x is the protocol and y the iteration. The spec
# leads the reference: the spec's version MUST always be >= this.
__protocol_version__ = "0.2"

__all__ = [
    "ProposedAction",
    "Decision",
    "Firewall",
    "Policy",
    "PolicyError",
    "BrokerRefusal",
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
