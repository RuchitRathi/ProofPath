"""Human approval state machine for one bounded non-destructive HTTP request."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from proofpath.canonical import canonical_json
from proofpath.schemas import Action, ActionName, ApprovalRequest, ApprovalState

_APPROVAL_SECRET = secrets.token_bytes(32)


def action_binding(action: Action) -> dict[str, object]:
    """Exact fields a human sees and approves; unrelated Action data is excluded."""
    if action.name != ActionName.ACTIVE_VALIDATE or len(action.ports) != 1:
        raise ValueError("approval can bind only one active_validate action and port")
    return {
        "target": action.target,
        "port": action.ports[0],
        "method": action.arguments.get("method"),
        "path": action.arguments.get("path"),
        "finding_id": action.arguments.get("finding_id"),
    }


def binding_hash(action: Action) -> str:
    return hashlib.sha256(canonical_json(action_binding(action)).encode("utf-8")).hexdigest()


def request_approval(action: Action, requested_by: str, justification: str, *, ttl_seconds: int = 300, now: datetime | None = None) -> ApprovalRequest:
    if action.name != ActionName.ACTIVE_VALIDATE:
        raise ValueError("approval request must describe active_validate")
    if not requested_by.strip():
        raise ValueError("requester identity is required")
    if action.arguments.get("method") not in {"GET", "HEAD"}:
        raise ValueError("active validation method must be GET or HEAD")
    if set(action.arguments) != {"method", "path", "finding_id"}:
        raise ValueError("active validation accepts only method, path, and finding_id")
    if ttl_seconds < 1 or ttl_seconds > 3600:
        raise ValueError("approval expiry must be between 1 and 3600 seconds")
    stamp = _utc(now)
    bound = action_binding(action)
    return ApprovalRequest(
        id=f"AP-{action.id}", action_id=action.id, requested_by=requested_by,
        justification=justification[:500], target=str(bound["target"]), port=int(bound["port"]),
        method=bound["method"], path=str(bound["path"]), finding_id=str(bound["finding_id"]),
        action_hash=binding_hash(action), expires_at=stamp + timedelta(seconds=ttl_seconds),
    )


def decide_approval(request: ApprovalRequest, decided_by: str, *, approved: bool, now: datetime | None = None) -> ApprovalRequest:
    if request.state != ApprovalState.PENDING:
        raise ValueError(f"approval cannot transition from {request.state.value}")
    if not decided_by.strip():
        raise ValueError("approver identity is required")
    if decided_by.strip() == request.requested_by.strip():
        raise ValueError("requester cannot approve or deny their own request")
    stamp = _utc(now)
    if stamp >= _utc(request.expires_at):
        decided = request.model_copy(update={"state": ApprovalState.EXPIRED, "decided_by": decided_by, "decided_at": stamp})
    else:
        decided = request.model_copy(update={"state": ApprovalState.APPROVED if approved else ApprovalState.DENIED, "decided_by": decided_by, "decided_at": stamp})
    return decided.model_copy(update={"decision_token": _decision_token(decided)})


def approval_matches_action(request: ApprovalRequest, action: Action, now: datetime | None = None) -> bool:
    if request.state != ApprovalState.APPROVED or request.used_at is not None or not hmac.compare_digest(request.decision_token, _decision_token(request)):
        return False
    if request.action_id != action.id or _utc(now) >= _utc(request.expires_at):
        return False
    try:
        return request.action_hash == binding_hash(action)
    except ValueError:
        return False


def consume_approval(request: ApprovalRequest, action: Action, now: datetime | None = None) -> ApprovalRequest:
    if not approval_matches_action(request, action, now):
        raise ValueError("approval is invalid, expired, used, or bound to a different action")
    return request.model_copy(update={"used_at": _utc(now)})


def _utc(value: datetime | None) -> datetime:
    stamp = value or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise ValueError("approval timestamps must include a timezone")
    return stamp.astimezone(timezone.utc)


def _decision_token(request: ApprovalRequest) -> str:
    payload = {
        "id": request.id, "action_id": request.action_id, "requested_by": request.requested_by,
        "decided_by": request.decided_by, "decided_at": request.decided_at.isoformat() if request.decided_at else None,
        "state": request.state.value, "action_hash": request.action_hash, "expires_at": request.expires_at.isoformat(),
    }
    return hmac.new(_APPROVAL_SECRET, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
