"""Typed records for actions, evidence, findings, and audit entries.

The proposer returns a candidate ID and rationale. Application code builds the
selected Action from a rule-generated candidate before the scope check.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator


class ActionName(str, Enum):
    """Closed action space. Unknown names never reach a tool."""

    NMAP_SCAN = "nmap_scan"
    NIKTO_SCAN = "nikto_scan"
    ZAP_SCAN = "zap_scan"
    IMPORT_NESSUS = "import_nessus"
    IMPORT_BURP = "import_burp"
    IMPORT_OPENVAS = "import_openvas"
    IMPORT_NIKTO = "import_nikto"
    IMPORT_ZAP = "import_zap"
    IMPORT_METASPLOIT = "import_metasploit"
    IMPORT_NMAP_XML = "import_nmap_xml"
    REQUEST_APPROVAL = "request_approval"
    ACTIVE_VALIDATE = "active_validate"
    GENERATE_REPORT = "generate_report"


class Action(BaseModel):
    """One structured request. Scope checks this object, not free text."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    name: ActionName
    target: str = Field(min_length=1, max_length=253)
    ports: list[StrictInt] = Field(default_factory=list)
    arguments: dict[str, Any] = Field(default_factory=dict)
    engagement_id: str = Field(min_length=1, max_length=64)
    requested_by: str = Field(default="analyst", min_length=1, max_length=64)

    @field_validator("ports")
    @classmethod
    def ports_are_real(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("ports must be integers from 1 to 65535")
        return ports


class ServiceObservation(BaseModel):
    """A port fact taken from tool output. This is observation, not inference."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    ip: str
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    locator: str = ""
    excerpt: str = Field(default="", max_length=300)
    source_mode: Literal["live", "imported"] = "live"


class Evidence(BaseModel):
    """Pointer to bytes in the ledger. The bytes are the artifact."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tool: str
    command: list[str]
    sha256: str
    captured_at: datetime
    artifact_path: str
    status: Literal["ok", "error", "timeout", "denied", "tool_not_found"]
    summary: str = ""
    source_mode: Literal["live", "imported"] = "live"

    @field_validator("captured_at")
    @classmethod
    def captured_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            raise ValueError("captured_at must be a UTC timestamp")
        return value


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: str
    locator: str
    excerpt: str = Field(max_length=300)


class FindingAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    hostname: str | None = None


class Finding(BaseModel):
    """A claim tied to evidence. Observed text and inference stay apart."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    asset: FindingAsset
    port: int
    protocol: str
    service: str | None = None
    source_tools: list[str] = Field(min_length=1)
    evidence: list[EvidenceRef] = Field(min_length=1)
    observed: str
    inference: str = ""
    severity: Literal["critical", "high", "medium", "low", "info", "not_provided"] = "not_provided"
    cvss: float | None = None
    cvss_vector: str | None = None
    exploit_available: bool | None = None
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    mapped_to: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    status: Literal["confirmed", "suspected", "false_positive_candidate", "refuted"]
    first_seen: datetime
    last_seen: datetime
    validation_status: Literal["not_validated", "validated_approved", "rejected_by_human"] = "not_validated"
    conflict_notes: list[str] = Field(default_factory=list)

    @field_validator("cves")
    @classmethod
    def valid_cves(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in values):
            raise ValueError("invalid CVE identifier")
        return values

    @field_validator("cwes")
    @classmethod
    def valid_cwes(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"CWE-\d+", value) for value in values):
            raise ValueError("invalid CWE identifier")
        return values

    @field_validator("cvss")
    @classmethod
    def cvss_in_range(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not 0.0 <= float(value) <= 10.0:
            raise ValueError("cvss must be between 0 and 10 or null")
        return float(value)

    @field_validator("inference")
    @classmethod
    def inference_is_labeled(cls, value: str) -> str:
        if value and not value.lower().startswith("inference:"):
            raise ValueError("non-empty inference must be labeled 'Inference:'")
        return value

    @field_validator("first_seen", "last_seen")
    @classmethod
    def timestamps_are_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            raise ValueError("finding timestamps must be UTC")
        return value


class Hypothesis(BaseModel):
    """A statement the skeptic can try to refute."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    evidence_for: list[EvidenceRef] = Field(default_factory=list)
    evidence_against: list[EvidenceRef] = Field(default_factory=list)
    status: Literal["open", "supported", "refuted"] = "open"


class ApprovalState(str, Enum):
    """States for the human approval record. Transitions live in code."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    """Human decision required before active validation can run."""

    model_config = ConfigDict(extra="forbid")

    id: str
    action_id: str
    requested_by: str
    justification: str
    target: str
    port: int
    method: Literal["GET", "HEAD"]
    path: str
    finding_id: str
    action_hash: str
    decision_token: str = ""
    expires_at: datetime
    used_at: datetime | None = None
    state: ApprovalState = ApprovalState.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None

    @field_validator("expires_at", "decided_at", "used_at")
    @classmethod
    def approval_timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must include a timezone")
        return value.astimezone(timezone.utc)


class AuditEntry(BaseModel):
    """One hash-chained event. entry_hash covers every field except itself."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    timestamp: str
    prev_hash: str
    entry_hash: str
    event_type: str
    actor: str
    details: dict[str, Any]


class GuardDecision(BaseModel):
    """Signed allow or deny. A tool must verify the token before it runs."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    resolved_ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    tool: str = ""
    normalized_arguments: dict[str, Any] = Field(default_factory=dict)
    action_id: str = ""
    token: str = ""


def format_cvss(value: float | None) -> str:
    """Display rule: a missing score is the words 'not provided'."""
    if value is None:
        return "not provided"
    return f"{value:.1f}"
