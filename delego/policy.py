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

**Load-time validation (fail-closed).** ``Policy.load`` validates the document
*before* it can gate anything. A misspelled constraint key (e.g. ``amount_max``)
or an unknown ``match`` key used to be silently dropped — a fail-*open* hole,
since a constraint the author intended would simply not be enforced. Loading now
raises :class:`PolicyError` on such a document. If ``jsonschema`` is installed it
is additionally validated against the vendored schema (a copy of the spec's
``schema/policy.json``); the hand-written checks run regardless, so validation
does not depend on that optional package.
"""

from __future__ import annotations

import fnmatch
import warnings
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import OUTCOME_ALLOW, OUTCOME_APPROVAL, OUTCOME_DENY, ProposedAction

# Valid outcomes. A *rule* may only allow or park (never hard-deny — that is what
# `forbidden` is for); the policy `default` may additionally be `deny`.
_RULE_DECISIONS = {OUTCOME_ALLOW, OUTCOME_APPROVAL}
_DEFAULT_OUTCOMES = {OUTCOME_DENY, OUTCOME_ALLOW, OUTCOME_APPROVAL}

# The keys each section accepts. Anything else is a typo or a misunderstanding,
# and (because an unrecognised key is silently ignored at runtime) a fail-open
# risk — so an unknown key is a hard load error.
_MATCH_KEYS = {"method", "host", "path", "path_contains"}
_CONSTRAINT_KEYS = {"amount", "allow_list", "rate_limit"}
_RULE_KEYS = {"name", "description", "decision", "match", "constraints"}
_FORBIDDEN_KEYS = {"name", "description", "match"}
_POLICY_KEYS = {"version", "default", "forbidden", "rules"}

# Keys accepted *inside* each constraint, so a misspelling like ``amount.maximum``
# is caught rather than silently ignored (fail-open). ``_RATE_LIMIT_WINDOWS`` is
# both the set of legal ``per`` values and the seconds each window spans.
_AMOUNT_KEYS = {"field", "max", "currency"}
_ALLOW_LIST_KEYS = {"field", "in"}
_RATE_LIMIT_KEYS = {"max", "per"}
_RATE_LIMIT_WINDOWS = {"minute": 60, "hour": 3600, "day": 86400}

# A minimal, vendored copy of the spec's schema/policy.json (spec §5). Vendored
# rather than read from the specification repo so validation works from the
# installed wheel, where that repo is not present. Used only when `jsonschema`
# is available; the hand-written checks below are authoritative either way.
POLICY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "delego policy",
    "type": "object",
    "required": ["default"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "integer", "minimum": 1, "default": 1},
        "default": {"enum": ["deny", "allow", "needs_approval"]},
        "forbidden": {"type": "array", "items": {"$ref": "#/$defs/forbiddenRule"}},
        "rules": {"type": "array", "items": {"$ref": "#/$defs/rule"}},
    },
    "$defs": {
        "match": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "method": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "host": {"type": "string"},
                "path": {"type": "string"},
                "path_contains": {"type": "string"},
            },
        },
        "forbiddenRule": {
            "type": "object",
            "required": ["name", "match"],
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "match": {"$ref": "#/$defs/match"},
            },
        },
        "rule": {
            "type": "object",
            "required": ["name", "decision", "match"],
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "decision": {"enum": ["allow", "needs_approval"]},
                "match": {"$ref": "#/$defs/match"},
                "constraints": {"$ref": "#/$defs/constraints"},
            },
        },
        "constraints": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "amount": {
                    "type": "object",
                    "required": ["field"],
                    "additionalProperties": False,
                    "properties": {
                        "field": {"type": "string"},
                        "max": {"type": "number"},
                        "currency": {"type": "string"},
                    },
                },
                "allow_list": {
                    "type": "object",
                    "required": ["field", "in"],
                    "additionalProperties": False,
                    "properties": {
                        "field": {"type": "string"},
                        "in": {"type": "array"},
                    },
                },
                "rate_limit": {
                    "type": "object",
                    "required": ["max"],
                    "additionalProperties": False,
                    "properties": {
                        "max": {"type": "integer", "minimum": 0},
                        "per": {"enum": ["minute", "hour", "day"]},
                    },
                },
            },
        },
    },
}


class PolicyError(ValueError):
    """A policy document is invalid and MUST NOT be used to authorise anything.

    Raised at load time. Refusing to load (rather than dropping the offending
    bit) keeps the firewall fail-closed: a policy you can't fully validate is one
    you can't trust to enforce what its author intended.
    """


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
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise PolicyError(f"policy at {p} is not valid YAML: {e}") from e
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise PolicyError(f"policy at {p} must be a mapping, got {type(data).__name__}")

        # Validate before constructing anything that could gate an action.
        _validate_policy(data, source=str(p))

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

    @property
    def has_rate_limit(self) -> bool:
        """Whether any rule carries a ``rate_limit`` constraint.

        The engine uses this to decide if a propose must run inside the audit
        ledger's transaction lock: a rate-limit count is exact only when the
        count→decide→append sequence is atomic (spec §5, consistency class).
        """
        return any("rate_limit" in r.constraints for r in self.rules)

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
# Validation  (fail-closed: an invalid policy never loads)
# --------------------------------------------------------------------------- #
def _validate_policy(data: dict[str, Any], *, source: str) -> None:
    """Reject a structurally or semantically invalid policy.

    Hand-written checks are authoritative (they run with no third-party deps and
    cover every fail-closed condition the spec requires); if ``jsonschema`` is
    installed the document is *additionally* checked against the vendored schema,
    so a future schema addition is caught even before a hand check is written.
    """
    problems: list[str] = []

    unknown_top = set(data) - _POLICY_KEYS
    if unknown_top:
        problems.append(f"unknown top-level key(s): {sorted(unknown_top)}")

    if "default" not in data:
        # The spec requires `default`; without it the firewall doesn't know its
        # fail-closed fallback. Treat a missing default as `deny` would be a
        # silent assumption, so demand it explicitly.
        problems.append("missing required key 'default'")
    else:
        default = data["default"]
        if default not in _DEFAULT_OUTCOMES:
            problems.append(
                f"default {default!r} is not one of {sorted(_DEFAULT_OUTCOMES)}"
            )
        elif default != OUTCOME_DENY:
            # Legal but dangerous: an allow/needs_approval default fails *open* for
            # everything no rule matched. Loud, not fatal.
            warnings.warn(
                f"delego policy {source}: default is {default!r}, not 'deny' — "
                "anything no rule matches will be permitted; 'deny' is strongly "
                "recommended (fail-closed).",
                stacklevel=3,
            )

    version = data.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        problems.append(f"version must be an integer >= 1, got {version!r}")

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        problems.append("'rules' must be a list")
        rules = []
    for i, r in enumerate(rules):
        problems.extend(_validate_rule(r, where=f"rules[{i}]"))

    forbidden = data.get("forbidden", [])
    if not isinstance(forbidden, list):
        problems.append("'forbidden' must be a list")
        forbidden = []
    for i, r in enumerate(forbidden):
        problems.extend(_validate_forbidden(r, where=f"forbidden[{i}]"))

    # Optional stronger check: the vendored JSON Schema, when jsonschema is present.
    problems.extend(_jsonschema_problems(data))

    if problems:
        bullets = "\n  - ".join(problems)
        raise PolicyError(
            f"invalid delego policy at {source} (refusing to load — fail-closed):"
            f"\n  - {bullets}"
        )


def _validate_rule(r: Any, *, where: str) -> list[str]:
    out: list[str] = []
    if not isinstance(r, dict):
        return [f"{where}: rule must be a mapping, got {type(r).__name__}"]
    unknown = set(r) - _RULE_KEYS
    if unknown:
        out.append(f"{where}: unknown rule key(s): {sorted(unknown)}")
    if not r.get("name") or not isinstance(r.get("name"), str):
        out.append(f"{where}: rule is missing a non-empty string 'name'")
    if "match" not in r:
        out.append(f"{where}: rule is missing 'match'")
    else:
        out.extend(_validate_match(r["match"], where=f"{where}.match"))
    decision = r.get("decision")
    if decision is None:
        out.append(f"{where}: rule is missing 'decision'")
    elif decision not in _RULE_DECISIONS:
        out.append(
            f"{where}: decision {decision!r} is not one of {sorted(_RULE_DECISIONS)}"
        )
    if "constraints" in r and r["constraints"] is not None:
        out.extend(_validate_constraints(r["constraints"], where=f"{where}.constraints"))
    return out


def _validate_forbidden(r: Any, *, where: str) -> list[str]:
    out: list[str] = []
    if not isinstance(r, dict):
        return [f"{where}: forbidden entry must be a mapping, got {type(r).__name__}"]
    unknown = set(r) - _FORBIDDEN_KEYS
    if unknown:
        out.append(f"{where}: unknown forbidden key(s): {sorted(unknown)}")
    if not r.get("name") or not isinstance(r.get("name"), str):
        out.append(f"{where}: forbidden entry is missing a non-empty string 'name'")
    if "match" not in r:
        out.append(f"{where}: forbidden entry is missing 'match'")
    else:
        out.extend(_validate_match(r["match"], where=f"{where}.match"))
    return out


def _validate_match(m: Any, *, where: str) -> list[str]:
    if not isinstance(m, dict):
        return [f"{where}: match must be a mapping, got {type(m).__name__}"]
    unknown = set(m) - _MATCH_KEYS
    if unknown:
        return [f"{where}: unknown match key(s): {sorted(unknown)} (allowed: {sorted(_MATCH_KEYS)})"]
    return []


def _validate_constraints(c: Any, *, where: str) -> list[str]:
    if not isinstance(c, dict):
        return [f"{where}: constraints must be a mapping, got {type(c).__name__}"]
    out: list[str] = []
    unknown = set(c) - _CONSTRAINT_KEYS
    if unknown:
        out.append(
            f"{where}: unknown constraint key(s): {sorted(unknown)} "
            f"(allowed: {sorted(_CONSTRAINT_KEYS)})"
        )
    # Validate the inner keys of each known constraint so a misspelling *inside*
    # a constraint (e.g. amount.maximum) is also caught, not silently ignored.
    amount = c.get("amount")
    if isinstance(amount, dict):
        bad = set(amount) - _AMOUNT_KEYS
        if bad:
            out.append(f"{where}.amount: unknown key(s): {sorted(bad)}")
        if "field" not in amount:
            out.append(f"{where}.amount: missing required 'field'")
    allow_list = c.get("allow_list")
    if isinstance(allow_list, dict):
        bad = set(allow_list) - _ALLOW_LIST_KEYS
        if bad:
            out.append(f"{where}.allow_list: unknown key(s): {sorted(bad)}")
        for req in ("field", "in"):
            if req not in allow_list:
                out.append(f"{where}.allow_list: missing required {req!r}")
    rate_limit = c.get("rate_limit")
    if isinstance(rate_limit, dict):
        bad = set(rate_limit) - _RATE_LIMIT_KEYS
        if bad:
            out.append(f"{where}.rate_limit: unknown key(s): {sorted(bad)}")
        if "max" not in rate_limit:
            out.append(f"{where}.rate_limit: missing required 'max'")
        if "per" in rate_limit and rate_limit["per"] not in _RATE_LIMIT_WINDOWS:
            out.append(
                f"{where}.rate_limit: per {rate_limit['per']!r} is not one of "
                f"{sorted(_RATE_LIMIT_WINDOWS)}"
            )
    return out


def _jsonschema_problems(data: dict[str, Any]) -> list[str]:
    """Validate against the vendored schema if ``jsonschema`` is importable.

    Returns a list of problem strings (empty if it passes or jsonschema is
    absent). delego does not depend on jsonschema, so this is strictly a bonus
    layer on top of the hand-written checks above.
    """
    try:
        from jsonschema import Draft202012Validator
    except Exception:  # not installed — hand-written checks already ran
        return []
    validator = Draft202012Validator(POLICY_SCHEMA)
    problems: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(map(str, err.path)) or "<root>"
        problems.append(f"schema: {loc}: {err.message}")
    return problems


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
    # Globbing is intentionally simple for now: fnmatch's ``*`` already spans
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
    if rate_limit:
        if audit is None:
            # A rate limit we cannot evaluate must not silently pass (fail-closed).
            return False, ["rate_limit: no audit log available to enforce the limit"]
        per = rate_limit.get("per", "hour")
        window = _RATE_LIMIT_WINDOWS.get(per, 3600)
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
    # Decimal, not float: avoids money rounding error, and lets us reject the
    # non-finite values that silently defeat a float cap (``float('nan') > cap``
    # is False, so a NaN amount would otherwise *pass* the limit — fail-open).
    # ``bool`` is an int subclass; exclude it so ``amount: true`` isn't "numeric".
    if isinstance(raw, bool):
        return False, f"amount: field '{fieldname}'={raw!r} is not numeric"
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, TypeError, ValueError):
        return False, f"amount: field '{fieldname}'={raw!r} is not numeric"
    if not value.is_finite():
        return False, f"amount: field '{fieldname}'={raw!r} is not a finite number"
    if value < 0:
        return False, f"amount: field '{fieldname}'={raw!r} must not be negative"

    currency = spec.get("currency")
    if currency is not None:
        actual = action.params.get("currency")
        if actual != currency:
            return False, f"amount: currency {actual!r} != required {currency!r}"

    cap = spec.get("max")
    if cap is not None:
        try:
            cap_value = Decimal(str(cap))
        except (InvalidOperation, TypeError, ValueError):
            return False, f"amount: policy max {cap!r} is not numeric"
        if value > cap_value:
            suffix = f" {currency}" if currency else ""
            return False, f"amount: {value:g} exceeds max {cap_value:g}{suffix}"

    return True, f"amount: {value:g} within max {spec.get('max')}"
