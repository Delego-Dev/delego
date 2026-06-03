"""The deterministic policy engine — the part that actually authorises.

Design rule: **no LLM call lives in this file.** Authorisation is pure,
inspectable Python. A language model can *advise* upstream, but the decision
that gates a credential is made here, outside the stochastic loop, so a prompt
injection cannot talk its way past it.

Evaluation order (first match wins):
  1. ``forbidden`` — hard blocks, always deny, checked first.
  2. ``rules``     — first matching rule decides (allow / needs_approval),
                     subject to its constraints. A matched rule whose
                     constraints fail becomes a deny (fail-closed).
  3. ``default``   — used when nothing matched (recommended: ``deny``).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import OUTCOME_ALLOW, OUTCOME_APPROVAL, OUTCOME_DENY, ProposedAction


@dataclass
class Rule:
    name: str
    decision: str
    match: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class Policy:
    version: int
    default: str
    rules: list[Rule]
    forbidden: list[Rule]

    @classmethod
    def load(cls, path) -> "Policy":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"No delego policy at {p}. Run `delego init --home {p.parent}` "
                f"to install a starter policy (or create policy.yaml yourself)."
            )
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        rules = [
            Rule(
                name=r["name"],
                decision=r.get("decision", OUTCOME_DENY),
                match=r.get("match", {}) or {},
                constraints=r.get("constraints", {}) or {},
                description=r.get("description", ""),
            )
            for r in data.get("rules", [])
        ]
        forbidden = [
            Rule(
                name=r["name"],
                decision=OUTCOME_DENY,
                match=r.get("match", {}) or {},
                description=r.get("description", ""),
            )
            for r in data.get("forbidden", [])
        ]
        default = data.get("default", OUTCOME_DENY)
        return cls(version=data.get("version", 1), default=default, rules=rules, forbidden=forbidden)

    def evaluate(self, action: ProposedAction, audit=None) -> tuple[str, Optional[str], list[str]]:
        """Return ``(outcome, rule_name, reasons)`` for a proposed action."""
        for fr in self.forbidden:
            if _matches(fr.match, action):
                return OUTCOME_DENY, fr.name, [f"forbidden: {fr.description or fr.name}"]

        for rule in self.rules:
            if _matches(rule.match, action):
                ok, reasons = _check_constraints(rule, action, audit)
                if not ok:
                    return OUTCOME_DENY, rule.name, reasons
                detail = reasons or [f"matched rule '{rule.name}'"]
                return rule.decision, rule.name, detail

        return self.default, None, [f"no rule matched; default = {self.default}"]


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def _matches(m: dict[str, Any], action: ProposedAction) -> bool:
    if not m:
        return False

    method = m.get("method")
    if method is not None:
        methods = [method] if isinstance(method, str) else method
        if action.method.upper() not in [x.upper() for x in methods]:
            return False

    host = m.get("host")
    if host is not None and host.lower() != action.host:
        return False

    path = m.get("path")
    if path is not None and not _glob(path, action.path):
        return False

    contains = m.get("path_contains")
    if contains is not None and contains not in action.path:
        return False

    return True


def _glob(pattern: str, path: str) -> bool:
    # v0.1 globbing is intentionally simple: fnmatch's ``*`` already spans
    # path separators, so ``**`` and ``*`` are treated alike. Good enough for
    # host/path scoping; swap for a real path matcher if you need precision.
    return fnmatch.fnmatch(path, pattern.replace("**", "*"))


# --------------------------------------------------------------------------- #
# Constraints  (deterministic, fail-closed)
# --------------------------------------------------------------------------- #
def _check_constraints(rule: Rule, action: ProposedAction, audit) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    c = rule.constraints or {}

    amount = c.get("amount")
    if amount:
        ok, reason = _check_amount(amount, action)
        if not ok:
            return False, [reason]
        reasons.append(reason)

    allow_list = c.get("allow_list")
    if allow_list:
        fieldname = allow_list["field"]
        allowed = allow_list.get("in", [])
        val = action.params.get(fieldname)
        if val not in allowed:
            return False, [f"allow_list: {fieldname}={val!r} not in {allowed}"]
        reasons.append(f"allow_list: {fieldname}={val!r} permitted")

    rate_limit = c.get("rate_limit")
    if rate_limit and audit is not None:
        per = rate_limit.get("per", "hour")
        window = {"minute": 60, "hour": 3600, "day": 86400}.get(per, 3600)
        cap = int(rate_limit.get("max", 0))
        used = audit.count_allows(rule.name, within_seconds=window)
        if used >= cap:
            return False, [f"rate_limit: {used}/{cap} per {per} already used"]
        reasons.append(f"rate_limit: {used + 1}/{cap} per {per}")

    return True, reasons


def _check_amount(spec: dict[str, Any], action: ProposedAction) -> tuple[bool, str]:
    fieldname = spec.get("field", "amount")
    raw = action.params.get(fieldname)
    if raw is None:
        return False, f"amount: action is missing field '{fieldname}'"
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return False, f"amount: field '{fieldname}'={raw!r} is not numeric"

    currency = spec.get("currency")
    if currency is not None:
        actual = action.params.get("currency")
        if actual != currency:
            return False, f"amount: currency {actual!r} != required {currency!r}"

    cap = spec.get("max")
    if cap is not None and value > float(cap):
        suffix = f" {currency}" if currency else ""
        return False, f"amount: {value:g} exceeds max {cap:g}{suffix}"

    return True, f"amount: {value:g} within max {spec.get('max')}"
