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

from .approval import STATUS_APPROVED, STATUS_DENIED, STATUS_PENDING, ApprovalStore
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


class Firewall:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        approvals: ApprovalStore,
        broker: BrokerAdapter | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.broker = broker or NullBroker()

    # ------------------------------------------------------------------ #
    def propose(self, action: ProposedAction) -> Decision:
        outcome, rule, reasons = self.policy.evaluate(action, self.audit)
        ih, fp = action.intent_hash, action.fingerprint

        if outcome == OUTCOME_APPROVAL:
            approval_id = self.approvals.create(
                action_fingerprint=fp, intent_hash=ih, summary=action.summary()
            )
            self.audit.append(
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
            return self._execute(action, rule, reasons, ih, fp, approval_id=None)

        # deny
        self.audit.append(
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
            return Decision(OUTCOME_DENY, None, [f"unknown approval id {approval_id!r}"], ih, fp)

        # --- confused-deputy guard ------------------------------------- #
        # The approval is bound to one exact action. A different action under
        # the same approval id is refused and recorded.
        if rec["action_fingerprint"] != fp:
            reasons = [
                "approval/action mismatch: this approval was issued for a different "
                "action (possible confused-deputy / substituted action)"
            ]
            self.audit.append(
                phase="execution",
                outcome=OUTCOME_DENY,
                rule=None,
                reasons=reasons,
                intent_hash=ih,
                action_fingerprint=fp,
                action_summary=action.summary(),
                approval_id=approval_id,
            )
            return Decision(OUTCOME_DENY, None, reasons, ih, fp, approval_id=approval_id)

        if rec["status"] == STATUS_PENDING:
            return Decision(
                OUTCOME_APPROVAL, None, ["awaiting human approval"], ih, fp, approval_id=approval_id
            )

        if rec["status"] == STATUS_DENIED:
            reasons = ["human denied this action"]
            self.audit.append(
                phase="execution",
                outcome=OUTCOME_DENY,
                rule=None,
                reasons=reasons,
                intent_hash=ih,
                action_fingerprint=fp,
                action_summary=action.summary(),
                approval_id=approval_id,
            )
            return Decision(OUTCOME_DENY, None, reasons, ih, fp, approval_id=approval_id)

        # approved
        reasons = [f"human approved by {rec.get('approver')!r}"]
        return self._execute(action, None, reasons, ih, fp, approval_id=approval_id)

    # ------------------------------------------------------------------ #
    def _execute(self, action, rule, reasons, intent_hash, fingerprint, approval_id) -> Decision:
        result = self.broker.execute(action)
        self.audit.append(
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
        )
