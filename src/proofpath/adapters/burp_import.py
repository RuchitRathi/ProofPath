"""Guarded importer for Burp issue XML exports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import urlsplit
import uuid
import xml.etree.ElementTree as ET

from proofpath.adapters.base import ToolResult, execute_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, GuardDecision
from proofpath.scope_guard import ScopeGuard
from proofpath.xml_evidence import XmlDocument, parse_xml_evidence
from proofpath.normalizer import normalize_burp

_SEVERITIES = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "information": "info", "informational": "info", "info": "info"}
_CONFIDENCE = {"certain": "high", "firm": "medium", "tentative": "low", "high": "high", "medium": "medium", "low": "low"}


@dataclass(frozen=True)
class BurpIssue:
    index: int
    title: str
    host_text: str
    host_ip_attribute: str | None
    target: str
    asset_ip: str | None
    hostname: str | None
    port: int | None
    protocol: str
    service: str | None
    path: str
    location: str
    severity: str
    confidence: str
    issue_background: str
    issue_detail: str
    remediation: str
    requestresponse_count: int
    request_present: bool
    response_present: bool
    request_base64: bool
    response_base64: bool
    locator: str
    excerpt: str


@dataclass(frozen=True)
class BurpImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_issues: int


def _burp_document(raw: bytes) -> XmlDocument:
    if len(raw) > 25_000_000:
        raise ValueError("Burp XML exceeds the 25000000-byte import limit")
    safe_xml = _strip_safe_burp_doctype(raw)
    return parse_xml_evidence(safe_xml, label="Burp")


def _strip_safe_burp_doctype(raw: bytes) -> bytes:
    """Remove one constrained internal DTD before parsing; entity resolution is never enabled."""
    matches = list(re.finditer(br"<!DOCTYPE\b", raw, flags=re.IGNORECASE))
    if not matches:
        if re.search(br"<!ENTITY\b", raw, flags=re.IGNORECASE):
            raise ValueError("Burp XML entity declarations are refused")
        return raw
    if len(matches) != 1:
        raise ValueError("Burp XML must contain at most one DOCTYPE")
    start = matches[0].start()
    quote: int | None = None
    bracket_depth = 0
    index = matches[0].end()
    subset_start: int | None = None
    subset_end: int | None = None
    doctype_end: int | None = None
    while index < len(raw):
        if raw[index:index + 4] == b"<!--":
            comment_end = raw.find(b"-->", index + 4)
            if comment_end < 0:
                raise ValueError("Burp XML has an unterminated DTD comment")
            index = comment_end + 3
            continue
        byte = raw[index]
        if quote is not None:
            if byte == quote:
                quote = None
        elif byte in (ord("'"), ord('"')):
            quote = byte
        elif byte == ord("["):
            if bracket_depth == 0:
                subset_start = index + 1
            bracket_depth += 1
        elif byte == ord("]"):
            if bracket_depth == 0:
                raise ValueError("Burp XML has an unmatched DTD subset bracket")
            bracket_depth -= 1
            if bracket_depth == 0:
                subset_end = index
        elif byte == ord(">") and bracket_depth == 0:
            doctype_end = index + 1
            break
        index += 1
    if doctype_end is None or quote is not None or bracket_depth:
        raise ValueError("Burp XML has an unterminated DOCTYPE")
    header_end = subset_start - 1 if subset_start is not None else doctype_end - 1
    header = raw[matches[0].end():header_end]
    if re.search(br"\b(?:SYSTEM|PUBLIC)\b", header, flags=re.IGNORECASE):
        raise ValueError("Burp XML external SYSTEM/PUBLIC identifiers are refused")
    if subset_start is not None:
        assert subset_end is not None
        subset = raw[subset_start:subset_end]
        _validate_burp_subset(subset)
    return raw[:start] + raw[doctype_end:]


def _validate_burp_subset(subset: bytes) -> None:
    index = 0
    while index < len(subset):
        while index < len(subset) and chr(subset[index]).isspace():
            index += 1
        if subset[index:index + 4] == b"<!--":
            end = subset.find(b"-->", index + 4)
            if end < 0:
                raise ValueError("Burp XML has an unterminated DTD comment")
            index = end + 3
            continue
        if index >= len(subset):
            break
        if subset[index:index + 2] != b"<!":
            if subset[index:index + 1] == b"%":
                raise ValueError("Burp XML parameter entity references are refused")
            raise ValueError("Burp XML DTD subset may contain only ELEMENT/ATTLIST declarations")
        name_match = re.match(br"<!\s*([A-Za-z]+)\b", subset[index:])
        if name_match is None:
            raise ValueError("Burp XML DTD declaration is malformed")
        declaration_type = name_match.group(1).upper()
        if declaration_type == b"ENTITY":
            raise ValueError("Burp XML entity declarations (general or parameter) are refused")
        if declaration_type not in {b"ELEMENT", b"ATTLIST"}:
            raise ValueError("Burp XML DTD subset may contain only ELEMENT/ATTLIST declarations")
        declaration_end = _find_declaration_end(subset, index + name_match.end())
        declaration = subset[index:declaration_end]
        if b"%" in declaration:
            raise ValueError("Burp XML parameter entity references are refused")
        index = declaration_end


def _find_declaration_end(data: bytes, index: int) -> int:
    quote: int | None = None
    while index < len(data):
        byte = data[index]
        if quote is not None:
            if byte == quote:
                quote = None
        elif byte in (ord("'"), ord('"')):
            quote = byte
        elif byte == ord(">"):
            return index + 1
        index += 1
    raise ValueError("Burp XML DTD declaration is unterminated")


def parse_burp_xml(raw: bytes) -> list[BurpIssue]:
    document = _burp_document(raw)
    if document.root.tag != "issues":
        raise ValueError("not a Burp issues XML document")
    parsed: list[BurpIssue] = []
    for index, element in enumerate(document.root.findall("issue"), 1):
        host_element = element.find("host")
        host_text = (host_element.text or "").strip() if host_element is not None else ""
        raw_ip_attribute = host_element.get("ip") if host_element is not None else None
        host_ip_attribute: str | None = None
        if raw_ip_attribute:
            try:
                host_ip_attribute = str(ipaddress.ip_address(raw_ip_attribute.strip()))
            except ValueError:
                host_ip_attribute = None
        parts = urlsplit(host_text if "://" in host_text else "//" + host_text)
        target = parts.hostname or host_text or host_ip_attribute or ""
        if not target:
            target = ""
        asset_ip: str | None = None
        hostname: str | None = None
        try:
            asset_ip = host_ip_attribute or str(ipaddress.ip_address(target))
        except ValueError:
            hostname = target or None
        try:
            port = parts.port
        except ValueError:
            port = None
        if port is None and host_element is not None and host_element.get("port"):
            try:
                port = int(host_element.get("port", ""))
            except ValueError:
                port = None
        if port is None and parts.scheme.lower() in {"http", "https"}:
            # URL semantics define the effective port when omitted.
            port = 443 if parts.scheme.lower() == "https" else 80
        protocol = "tcp"
        scheme = parts.scheme.lower()
        service = scheme if scheme in {"http", "https"} else ""
        locator = f"/issues/issue[{index}]"
        raw_severity = _text(element, "severity").strip().lower()
        raw_confidence = _text(element, "confidence").strip().lower()
        parsed.append(
            BurpIssue(
                index=index,
                title=_text(element, "name").strip() or "Burp issue",
                host_text=host_text,
                target=target,
                asset_ip=asset_ip,
                hostname=hostname,
                port=port,
                protocol=protocol,
                service=service or None,
                path=_text(element, "path"),
                location=_text(element, "location"),
                severity=_SEVERITIES.get(raw_severity, "not_provided"),
                confidence=_CONFIDENCE.get(raw_confidence, "low"),
                issue_background=_text(element, "issueBackground"),
                issue_detail=_text(element, "issueDetail"),
                remediation=_text(element, "remediationDetail") or _text(element, "remediationBackground") or _text(element, "remediation"),
                host_ip_attribute=host_ip_attribute,
                requestresponse_count=max(
                    len(element.findall("requestresponse")),
                    int(bool(element.findall("request")) or bool(element.findall("response"))),
                ),
                request_present=bool(element.findall(".//request")),
                response_present=bool(element.findall(".//response")),
                request_base64=_base64(element.find(".//request")),
                response_base64=_base64(element.find(".//response")),
                locator=locator,
                excerpt=document.excerpt(locator),
            )
        )
    return parsed


def import_burp_xml(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> BurpImportResult:
    issues = parse_burp_xml(raw)
    evidence = ledger.store(content=raw, tool="burp", command=["import_burp"], status="ok", summary=f"imported Burp XML with {len(issues)} issues", source_mode="imported")
    audit.append("burp_import_started", actor, {"evidence_id": evidence.id, "source_mode": "imported", "issue_count": len(issues)})
    findings: list[Finding] = []
    dropped = 0
    for issue in issues:
        if not issue.target or issue.port is None or not 1 <= issue.port <= 65535:
            audit.append("out_of_scope", actor, {"evidence_id": evidence.id, "host": issue.host_text, "port": issue.port, "reason": "Burp issue has no valid target or effective port"})
            dropped += 1
            continue
        action = Action(id=uuid.uuid4().hex, name=ActionName.IMPORT_BURP, target=issue.target, ports=[issue.port], arguments={}, engagement_id=guard.policy.engagement, requested_by=actor)
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_BURP: BurpIssueAdapter(issue, evidence.id, evidence.captured_at)})
        if not result.decision.allowed:
            audit.append("out_of_scope", actor, {"evidence_id": evidence.id, "host": issue.host_text, "port": issue.port, "reason": result.decision.reason})
            dropped += 1
        else:
            findings.extend(result.findings)
    return BurpImportResult(evidence_id=evidence.id, sha256=evidence.sha256, parsed_items=len(issues), findings=findings, dropped_issues=dropped)


class BurpIssueAdapter:
    mode = "Import-only"

    def __init__(self, issue: BurpIssue, evidence_id: str, captured_at: datetime) -> None:
        self.issue = issue
        self.evidence_id = evidence_id
        self.captured_at = captured_at

    def run(self, decision: GuardDecision, guard: ScopeGuard, audit: AuditLog, ledger: Ledger, actor: str) -> ToolResult:
        if not decision.allowed or decision.tool != "burp" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified Burp import allow"})
            return ToolResult(status="denied", decision=decision, message="Burp import denied")
        if self.issue.asset_ip is not None and self.issue.asset_ip not in decision.resolved_ips:
            return ToolResult(status="denied", decision=decision, message="Burp host IP attribute does not match the scope-checked host")
        findings = normalize_burp(self.issue, self.evidence_id, self.captured_at, decision.resolved_ips)
        audit.append("burp_finding_imported", actor, {"action_id": decision.action_id, "evidence_id": self.evidence_id, "finding_ids": [finding.id for finding in findings], "locator": self.issue.locator, "source_mode": "imported"})
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=findings, message=f"Imported {len(findings)} Burp finding(s)")


def _text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text or "" if child is not None else ""


def _base64(element: ET.Element | None) -> bool:
    return element is not None and (element.get("base64") or "").lower() == "true"
