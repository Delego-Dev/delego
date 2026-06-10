"""The Firewall: the decision pipeline that ties everything together.

Two entry points:

* ``propose(action)`` — evaluate an action. Allowed actions are executed
  immediately (via the broker) and a receipt is written. Denied actions are
  recorded and refused. ``needs_approval`` actions are parked and an approval id
  is returned.

* ``resolve(approval_id, action)`` — after a human has decided, release (or
  refuse) the parked action. This is where the **confused-deputy guard** lives:
  the presented action's fingerprint must match the one the approval was issued
  for, otherwise it is denied as a substituted action.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .approval import (
    STATUS_APPROVED,
    STATUS_CONSUMED,
    STATUS_DENIED,
    STATUS_PENDING,
    ApprovalStore,
)
from .audit import AuditLog
from .brokers import BrokerAdapter, NullBroker
from .models import (
    OUTCOME_ALLOW,
    OUTCOME_APPROVAL,
    OUTCOME_DENY,
    Decision,
    ProposedAction,
)
from .policy import Policy

if TYPE_CHECKING:
    from .token import TokenIssuer


class Firewall:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        approvals: ApprovalStore,
        broker: BrokerAdapter | None = None,
        token_issuer: "TokenIssuer | None" = None,
        token_audience: str = "broker:default",
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.broker = broker or NullBroker()
        # Optional §9 profile: when wired, the firewall mints a short-lived
        # authorization token for `allow` outcomes (and released approvals) and
        # attaches it to the Decision for a separated broker to verify. Default
        # off — the in-process broker already trusts the decision, so behaviour
        # and receipts are unchanged when this is None.
        self.token_issuer = token_issuer
        self.token_audience = token_audience

    # ------------------------------------------------------------------ #
    def propose(self, action: ProposedAction) -> Decision:
        # A rate_limit is exact only if its count→decide→append sequence is
        # atomic: two concurrent proposes must not both read `used < max` before
        # either appends its allow. For rate-limited policies the whole pipeline
        # runs inside the ledger's transaction (file) lock — which also means
        # the broker call holds that lock; keep broker timeouts modest.
        if self.policy.has_rate_limit:
            with self.audit.transaction() as audit:
                return self._propose(action, audit)
        return self._propose(action, self.audit)

    def _propose(self, action: ProposedAction, audit) -> Decision:
        outcome, rule, reasons = self.policy.evaluate(action, audit)
        ih, fp = action.intent_hash, action.fingerprint

        if outcome == OUTCOME_APPROVAL:
            approval_id = self.approvals.create(
                action_fingerprint=fp,
                intent_hash=ih,
                summary=action.summary(),
                instruction=action.instruction,
                rule=rule,
            )
            audit.append(
                phase="decision",
                outcome=OUTCOME_APPROVAL,
                rule=rule,
                reasons=reasons,
                intent_hash=ih,
                action_fingerprint=fp,
                action_summary=action.summary(),
                approval_id=approval_id,
            )
            return Decision(OUTCOME_APPROVAL, rule, reasons, ih, fp, approval_id=approval_id)

        if outcome == OUTCOME_ALLOW:
            return self._execute(action, rule, reasons, ih, fp, approval_id=None, audit=audit)

        # deny
        audit.append(
            phase="decision",
            outcome=OUTCOME_DENY,
            rule=rule,
            reasons=reasons,
            intent_hash=ih,
            action_fingerprint=fp,
            action_summary=action.summary(),
        )
        return Decision(OUTCOME_DENY, rule, reasons, ih, fp)

    # ------------------------------------------------------------------ #
    def resolve(self, approval_id: str, action: ProposedAction) -> Decision:
        rec = self.approvals.get(approval_id)
        ih, fp = action.intent_hash, action.fingerprint

        if rec is None:
            # Recorded like every other refusal in this flow (spec §7): probing
            # invalid approval ids must leave evidence, not a silent deny.
            return self._refuse(action, ih, fp, approval_id, f"unknown approval id {approval_id!r}")

        # --- confused-deputy guard ------------------------------------- #
        # The approval is bound to one exact action. A different action under
        # the same approval id is refused and recorded.
        if rec["action_fingerprint"] != fp:
            # Naming the approved action lets a well-meaning caller correct a
            # drifted parameter and re-present; the summary is already visible
            # via `delego pending` and the ledger, so nothing new is revealed.
            return self._refuse(
                action,
                ih,
                fp,
                approval_id,
                "approval/action mismatch: this approval was issued for a different "
                "action (possible confused-deputy / substituted action); the "
                f"approval was issued for: {rec.get('summary')}",
            )

        # --- intent guard ---------------------------------------------- #
        # The approval is also bound to the instruction that authorised it. The
        # same action carried under a different instruction is refused, so the
        # human's "yes" can't be re-pointed at a new claimed authority.
        if rec.get("intent_hash") != ih:
            return self._refuse(
                action,
                ih,
                fp,
                approval_id,
                "approval/intent mismatch: this approval was issued for a different "
                f"instruction; the approval was issued for: {rec.get('instruction')!r}",
            )

        if rec["status"] == STATUS_PENDING:
            return Decision(
                OUTCOME_APPROVAL, None, ["awaiting human approval"], ih, fp, approval_id=approval_id
            )

        if rec["status"] == STATUS_DENIED:
            return self._refuse(action, ih, fp, approval_id, "human denied this action")

        # --- single-use guard ------------------------------------------ #
        # An approval releases its action exactly once. A replayed resolve of an
        # already-consumed approval is refused, so one human "yes" can't be
        # executed again and again.
        if rec["status"] == STATUS_CONSUMED:
            return self._refuse(
                action,
                ih,
                fp,
                approval_id,
                "approval already used: this single-use approval has already released "
                "its action",
            )

        # approved — consume *before* executing so it can never be replayed, even
        # if execution is retried.
        assert rec["status"] == STATUS_APPROVED
        self.approvals.consume(approval_id)
        reasons = [f"human approved by {rec.get('approver')!r}"]
        return self._execute(
            action, rec.get("rule"), reasons, ih, fp, approval_id=approval_id, audit=self.audit
        )

    # ------------------------------------------------------------------ #
    def _refuse(self, action, intent_hash, fingerprint, approval_id, reason) -> Decision:
        """Record an execution-phase deny on the ledger and return it."""
        reasons = [reason]
        self.audit.append(
            phase="execution",
            outcome=OUTCOME_DENY,
            rule=None,
            reasons=reasons,
            intent_hash=intent_hash,
            action_fingerprint=fingerprint,
            action_summary=action.summary(),
            approval_id=approval_id,
        )
        return Decision(OUTCOME_DENY, None, reasons, intent_hash, fingerprint, approval_id=approval_id)

    # ------------------------------------------------------------------ #
    def _execute(
        self, action, rule, reasons, intent_hash, fingerprint, approval_id, audit
    ) -> Decision:
        """Run the broker, then record the execution receipt.

        ``audit`` is the handle to append with: the in-transaction view when
        called under :meth:`propose`'s rate-limit lock (the lock is not
        re-entrant), the plain log (``self.audit``) otherwise.

        A broker that refuses or fails MUST still leave a receipt (spec §8:
        every decision and execution is recorded) — otherwise the very refusal
        the broker is proud of catching is invisible in the ledger, and a
        crash between authorisation and execution leaves no trace the action
        was ever authorised. The failure is recorded as an ``execution``/deny
        receipt and the exception re-raised for the caller.

        If a token issuer is configured, a §9 authorization token is minted for
        this `allow` and handed to the broker (which MAY verify it before
        injecting) and returned on the Decision.
        """
        token = self._mint_token(rule, intent_hash, fingerprint, approval_id)
        try:
            result = self._broker_execute(action, token)
        except Exception as e:
            audit.append(
                phase="execution",
                outcome=OUTCOME_DENY,
                rule=rule,
                reasons=reasons + [f"broker did not execute: {e}"],
                intent_hash=intent_hash,
                action_fingerprint=fingerprint,
                action_summary=action.summary(),
                approval_id=approval_id,
            )
            raise
        audit.append(
            phase="execution",
            outcome=OUTCOME_ALLOW,
            rule=rule,
            reasons=reasons + ["executed via broker"],
            intent_hash=intent_hash,
            action_fingerprint=fingerprint,
            action_summary=action.summary(),
            approval_id=approval_id,
        )
        return Decision(
            OUTCOME_ALLOW,
            rule,
            reasons,
            intent_hash,
            fingerprint,
            approval_id=approval_id,
            executed=True,
            result=result,
            token=token,
        )

    # ------------------------------------------------------------------ #
    def _mint_token(self, rule, intent_hash, fingerprint, approval_id):
        """Mint a §9 token for an `allow`, or None if no issuer is configured.

        Only ever called from :meth:`_execute`, i.e. for `allow` and released
        approvals — never for `deny`/`needs_approval`/`denied`/`consumed`, which
        per spec §9 MUST NOT mint."""
        if self.token_issuer is None:
            return None
        return self.token_issuer.mint(
            action_fingerprint=fingerprint,
            intent_hash=intent_hash,
            audience=self.token_audience,
            approval_id=approval_id,
            policy_version=self.policy.version,
            rule=rule,
        )

    def _broker_execute(self, action, token):
        """Call the broker, passing the token when the broker accepts one.

        Brokers MAY take an optional ``token`` keyword (the shipped adapters do);
        a 0.2/0.3-era adapter with a bare ``execute(action)`` keeps working."""
        if token is None:
            return self.broker.execute(action)
        try:
            return self.broker.execute(action, token=token)
        except TypeError:
            # Broker predates the token kwarg — fall back, unchanged behaviour.
            return self.broker.execute(action)
