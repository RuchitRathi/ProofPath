"""The execution choke point. Tools run only after a signed allow."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, ApprovalRequest, Finding, GuardDecision, ServiceObservation
from proofpath.scope_guard import ScopeGuard


class ToolResult(BaseModel):
    """What the UI and the audit trail show after an action."""

    model_config = ConfigDict(extra="forbid")

    status: str
    decision: GuardDecision
    evidence_id: str | None = None
    sha256: str | None = None
    services: list[ServiceObservation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    parsed_items: int = 0
    dropped_items: int = 0
    message: str


class ToolAdapter(Protocol):
    """An adapter that receives a decision already produced by the guard."""

    def run(
        self,
        decision: GuardDecision,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        """Execute only when the decision is a signed allow for this tool."""


def execute_action(
    action: Action,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    adapters: dict[ActionName, ToolAdapter],
    *,
    approval: ApprovalRequest | None = None,
) -> ToolResult:
    """Check scope, write the decision to the audit log, then maybe run a tool."""
    decision = guard.check(action, approval=approval)
    if not guard.verify_decision(decision):
        raise RuntimeError("scope guard returned an unsigned decision")
    audit.append(
        "scope_decision",
        action.requested_by,
        {
            "action_id": action.id,
            "action": action.name.value,
            "target": action.target,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "resolved_ips": decision.resolved_ips,
            "ports": list(decision.ports),
        },
    )
    if not decision.allowed:
        return ToolResult(status="denied", decision=decision, message=decision.reason)
    adapter = adapters.get(action.name)
    if adapter is None:
        audit.append(
            "execution_blocked",
            action.requested_by,
            {"action_id": action.id, "reason": "no adapter is registered"},
        )
        return ToolResult(
            status="error",
            decision=decision,
            message="no adapter is registered for this action",
        )
    return adapter.run(decision, guard, audit, ledger, action.requested_by)
