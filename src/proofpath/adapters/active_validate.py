"""One approval-gated, body-free HTTP GET/HEAD validation request."""

from __future__ import annotations

import http.client

from proofpath.adapters.base import ToolResult
from proofpath.approval import approval_matches_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ApprovalRequest, GuardDecision
from proofpath.scope_guard import ScopeGuard

MAX_RESPONSE_BYTES = 4096


class ActiveValidationAdapter:
    mode = "Live"

    def __init__(self, action: Action, approval: ApprovalRequest, *, timeout_seconds: float = 5.0) -> None:
        self.action = action
        self.approval = approval
        self.timeout_seconds = timeout_seconds

    def run(self, decision: GuardDecision, guard: ScopeGuard, audit: AuditLog, ledger: Ledger, actor: str) -> ToolResult:
        expected_arguments = {key: self.action.arguments.get(key) for key in ("method", "path", "finding_id")}
        if (
            not decision.allowed
            or decision.tool != "active_validate"
            or decision.action_id != self.action.id
            or decision.ports != self.action.ports
            or decision.normalized_arguments != expected_arguments
            or not decision.resolved_ips
            or not guard.verify_decision(decision)
        ):
            audit.append("execution_blocked", actor, {"action_id": self.action.id, "reason": "decision was not a verified active validation allow"})
            return ToolResult(status="denied", decision=decision, message="active validation denied")
        if not approval_matches_action(self.approval, self.action) or not guard.consume_approval(self.approval, self.action):
            audit.append("execution_blocked", actor, {"action_id": self.action.id, "reason": "approval invalid, expired, mismatched, or already used"})
            return ToolResult(status="denied", decision=decision, message="approval invalid or already used")

        ip_address = decision.resolved_ips[0]
        method = str(decision.normalized_arguments["method"])
        path = str(decision.normalized_arguments["path"])
        audit.append("active_validation_execution", actor, {
            "action_id": self.action.id, "approval_id": self.approval.id,
            "target": self.action.target, "resolved_ip": ip_address, "port": self.action.ports[0],
            "method": method, "path": path, "finding_id": decision.normalized_arguments["finding_id"],
        })
        connection = http.client.HTTPConnection(ip_address, self.action.ports[0], timeout=self.timeout_seconds)
        try:
            connection.request(method, path)  # No body or analyst/model-controlled headers.
            response = connection.getresponse()  # Redirects are recorded, never followed.
            body = response.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(body) > MAX_RESPONSE_BYTES
            body = body[:MAX_RESPONSE_BYTES]
            headers = {name.lower(): value[:200] for name, value in response.getheaders() if name.lower() in {"content-type", "server", "location"}}
            excerpt = body.decode("utf-8", errors="replace")[:500]
            content = body
            outcome = {"status_code": response.status, "headers": headers, "excerpt": excerpt, "truncated": truncated}
            status = "validated_approved"
            result_status = "ok"
            message = f"HTTP {response.status}; redirects were not followed"
        except (OSError, http.client.HTTPException) as exc:
            content = f"{type(exc).__name__}: {exc}".encode("utf-8", errors="replace")[:MAX_RESPONSE_BYTES]
            outcome = {"error": f"{type(exc).__name__}: {exc}"[:300]}
            status = "not_validated"
            result_status = "error"
            message = "active validation request failed: " + outcome["error"]
        finally:
            connection.close()

        evidence = ledger.store(content=content, tool="active_validate", command=[method, path], status="ok" if result_status == "ok" else "error", summary=f"approved HTTP validation outcome for {self.action.id}", source_mode="live")
        audit.append("active_validation_outcome", actor, {
            "action_id": self.action.id, "approval_id": self.approval.id,
            "requested_by": self.approval.requested_by, "approved_by": self.approval.decided_by,
            "decided_at": self.approval.decided_at.isoformat() if self.approval.decided_at else None,
            "finding_id": decision.normalized_arguments["finding_id"], "validation_status": status,
            "evidence_id": evidence.id, "sha256": evidence.sha256, **outcome,
        })
        return ToolResult(status=result_status, decision=decision, evidence_id=evidence.id, sha256=evidence.sha256, message=message)
