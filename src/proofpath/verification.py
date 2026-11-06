"""Cross-check report records and approval lifecycle against the audit and ledger."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from proofpath.approval import binding_hash
from proofpath.schemas import Action


def verify_report_and_approvals(entries: list[Any], known_evidence: set[str], ledger: Any) -> tuple[bool, str]:
    requests: dict[str, dict[str, Any]] = {}
    decisions: dict[str, dict[str, Any]] = {}
    executions: set[str] = set()
    outcomes: set[str] = set()
    for entry in entries:
        detail = entry.details
        if entry.event_type == "approval_requested":
            approval_id = detail.get("approval_id")
            action_payload = detail.get("action")
            if not isinstance(approval_id, str) or not isinstance(action_payload, dict):
                return False, f"approval request at audit seq {entry.seq} has no real action"
            try:
                action = Action.model_validate(action_payload)
                digest = binding_hash(action)
            except Exception:
                return False, f"approval request at audit seq {entry.seq} references an invalid action"
            if action.id != detail.get("action_id") or digest != detail.get("action_hash"):
                return False, f"approval request {approval_id} action binding mismatch"
            requests[approval_id] = {"action_id": action.id, "requested_by": detail.get("requested_by"), "action_hash": digest}
        elif entry.event_type == "approval_decision":
            approval_id = detail.get("approval_id")
            request = requests.get(approval_id)
            if request is None:
                return False, f"approval decision at audit seq {entry.seq} references missing request {approval_id}"
            if detail.get("action_id") != request["action_id"] or detail.get("action_hash") != request["action_hash"]:
                return False, f"approval decision {approval_id} references a different action"
            if entry.actor == request["requested_by"]:
                return False, f"approval decision {approval_id} is self-approved"
            if detail.get("state") not in {"approved", "denied", "expired"}:
                return False, f"approval decision {approval_id} has an invalid state"
            decisions[approval_id] = detail
        elif entry.event_type == "active_validation_execution":
            approval_id = detail.get("approval_id")
            decision = decisions.get(approval_id)
            request = requests.get(approval_id)
            if decision is None or decision.get("state") != "approved" or request is None:
                return False, f"active validation at audit seq {entry.seq} has no approved request {approval_id}"
            if detail.get("action_id") != request["action_id"]:
                return False, f"active validation {approval_id} references a different action"
            executions.add(approval_id)
        elif entry.event_type == "active_validation_outcome":
            approval_id = detail.get("approval_id")
            if approval_id not in executions:
                return False, f"active validation outcome references missing execution {approval_id}"
            if detail.get("evidence_id") not in known_evidence:
                return False, f"active validation outcome references missing evidence {detail.get('evidence_id')}"
            outcomes.add(approval_id)
        elif entry.event_type == "report_generated":
            report_path = Path(str(detail.get("report_path", "")))
            expected_hash = detail.get("report_sha256")
            try:
                actual_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
            except OSError:
                return False, f"report missing: {report_path}"
            if actual_hash != expected_hash:
                return False, f"report hash mismatch: {report_path}"
            evidence_ids = detail.get("evidence_ids", [])
            evidence_hashes = detail.get("evidence_hashes", {})
            for evidence_id in evidence_ids:
                if evidence_id not in known_evidence:
                    return False, f"report cites missing evidence ID {evidence_id}"
                if not isinstance(evidence_hashes, dict) or evidence_id not in evidence_hashes:
                    return False, f"report is missing recorded hash for {evidence_id}"
                try:
                    actual_evidence_hash = ledger.load(evidence_id).sha256
                except Exception:
                    return False, f"report cites invalid evidence {evidence_id}"
                if evidence_hashes[evidence_id] != actual_evidence_hash:
                    return False, f"report evidence hash mismatch: {evidence_id}"
    for approval_id in executions:
        if approval_id not in outcomes:
            return False, f"active validation {approval_id} has no recorded outcome"
    return True, "report hashes and approval references verified"
