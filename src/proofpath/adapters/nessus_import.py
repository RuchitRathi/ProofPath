"""Guarded importer for NessusClientData_v2 XML exports."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import ipaddress
import math
import re
from typing import Any
import uuid
import xml.etree.ElementTree as ET

from proofpath.adapters.base import ToolResult, execute_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, Finding, GuardDecision
from proofpath.scope_guard import ScopeGuard
from proofpath.xml_evidence import XmlDocument, parse_xml_evidence
from proofpath.normalizer import normalize_nessus

_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class NessusItem:
    host_name: str
    target: str
    asset_ip: str | None
    hostname: str | None
    port: int | None
    protocol: str
    service: str | None
    plugin_id: str
    plugin_name: str
    severity: str
    description: str
    plugin_output: str
    cvss: float | None
    cvss_vector: str | None
    cves: list[str]
    cwes: list[str]
    exploit_available: bool | None
    locator: str
    excerpt: str
    host_index: int
    item_index: int


@dataclass(frozen=True)
class NessusImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_items: int


def parse_nessus_xml(raw: bytes) -> tuple[XmlDocument, list[NessusItem]]:
    document = parse_xml_evidence(raw, label="Nessus")
    if document.root.tag != "NessusClientData_v2":
        raise ValueError("not a NessusClientData_v2 document")
    report = document.root.find("Report")
    if report is None:
        raise ValueError("Nessus XML is missing Report")
    items: list[NessusItem] = []
    for host_index, host in enumerate(report.findall("ReportHost"), 1):
        host_name = host.get("name") or ""
        host_ip = _host_ip(host)
        if not host_ip:
            try:
                host_ip = str(ipaddress.ip_address(host_name))
            except ValueError:
                host_ip = None
        hostname = host_name if host_ip is None or host_name != host_ip else None
        target = host_ip or host_name
        host_locator = f"/NessusClientData_v2/Report[1]/ReportHost[{host_index}]"
        for item_index, element in enumerate(host.findall("ReportItem"), 1):
            locator = f"{host_locator}/ReportItem[{item_index}]"
            severity_raw = element.get("severity", "")
            items.append(
                NessusItem(
                    host_name=host_name,
                    target=target,
                    asset_ip=host_ip,
                    hostname=hostname,
                    port=_integer(element.get("port")),
                    protocol=element.get("protocol", "not_provided") or "not_provided",
                    service=element.get("svc_name"),
                    plugin_id=element.get("pluginID", ""),
                    plugin_name=element.get("pluginName", ""),
                    severity=_SEVERITY.get(severity_raw, "not_provided"),
                    description=_text(element, "description"),
                    plugin_output=_text(element, "plugin_output"),
                    cvss=_score(_text(element, "cvss3_base_score") or _text(element, "cvss_base_score")),
                    cvss_vector=_text(element, "cvss3_vector") or _text(element, "cvss_vector") or None,
                    cves=_identifiers(element.findall("cve"), _CVE),
                    cwes=_identifiers(element.findall("cwe"), _CWE),
                    exploit_available=_optional_bool(_text(element, "exploit_available")),
                    locator=locator,
                    excerpt=document.excerpt(locator),
                    host_index=host_index,
                    item_index=item_index,
                )
            )
    return document, items


def import_nessus_xml(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> NessusImportResult:
    """Store the raw report once, then guard every host/port item independently."""
    _document, items = parse_nessus_xml(raw)
    evidence = ledger.store(content=raw, tool="nessus", command=["import_nessus"], status="ok", summary=f"imported Nessus XML with {len(items)} report items", source_mode="imported")
    audit.append("nessus_import_started", actor, {"evidence_id": evidence.id, "source_mode": "imported", "item_count": len(items)})
    findings: list[Finding] = []
    dropped = 0
    for item in items:
        if not item.target or item.port is None or not 1 <= item.port <= 65535:
            audit.append("out_of_scope", actor, {"evidence_id": evidence.id, "host": item.host_name, "port": item.port, "reason": "missing or invalid target port"})
            dropped += 1
            continue
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.IMPORT_NESSUS,
            target=item.target,
            ports=[item.port],
            arguments={},
            engagement_id=guard.policy.engagement,
            requested_by=actor,
        )
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_NESSUS: NessusItemAdapter(item, evidence.id, evidence.captured_at)})
        if not result.decision.allowed:
            audit.append("out_of_scope", actor, {"evidence_id": evidence.id, "host": item.host_name, "port": item.port, "reason": result.decision.reason})
            dropped += 1
        else:
            findings.extend(result.findings)
    return NessusImportResult(evidence_id=evidence.id, sha256=evidence.sha256, parsed_items=len(items), findings=findings, dropped_items=dropped)


class NessusItemAdapter:
    mode = "Import-only"

    def __init__(self, item: NessusItem, evidence_id: str, captured_at: datetime) -> None:
        self.item = item
        self.evidence_id = evidence_id
        self.captured_at = captured_at

    def run(self, decision: GuardDecision, guard: ScopeGuard, audit: AuditLog, ledger: Ledger, actor: str) -> ToolResult:
        if not decision.allowed or decision.tool != "nessus" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified Nessus import allow"})
            return ToolResult(status="denied", decision=decision, message="Nessus import denied")
        if (self.item.asset_ip is not None and self.item.asset_ip not in decision.resolved_ips) or self.item.port not in decision.ports:
            return ToolResult(status="denied", decision=decision, message="Nessus item does not match the verified target and port")
        findings: list[Finding] = []
        for address in decision.resolved_ips:
            if self.item.asset_ip is not None and address != self.item.asset_ip:
                continue
            normalized_item = self.item if self.item.asset_ip is not None else replace(self.item, asset_ip=address, hostname=self.item.host_name or None)
            finding = normalize_nessus(normalized_item, self.evidence_id, self.captured_at)
            if finding is not None:
                findings.append(finding)
        if not findings:
            return ToolResult(status="error", decision=decision, message="Nessus item could not be normalized")
        audit.append("nessus_finding_imported", actor, {"action_id": decision.action_id, "evidence_id": self.evidence_id, "finding_ids": [finding.id for finding in findings], "locator": self.item.locator, "source_mode": "imported"})
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=findings, message=f"Imported {len(findings)} Nessus finding(s)")


def _host_ip(host: ET.Element) -> str | None:
    properties = host.find("HostProperties")
    if properties is None:
        return None
    for tag in properties.findall("tag"):
        if tag.get("name") == "host-ip" and tag.text:
            try:
                return str(ipaddress.ip_address(tag.text.strip()))
            except ValueError:
                return None
    return None


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text or "" if child is not None else ""


def _score(value: str) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None


def _optional_bool(value: str) -> bool | None:
    normalized = value.strip().casefold()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def _identifiers(elements: list[ET.Element], pattern: re.Pattern[str]) -> list[str]:
    found: list[str] = []
    for element in elements:
        value = (element.text or "").strip()
        if pattern.fullmatch(value) and value not in found:
            found.append(value)
    return found
