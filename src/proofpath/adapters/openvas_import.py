"""Guarded importer for OpenVAS / Greenbone XML report exports."""

from __future__ import annotations

from dataclasses import dataclass
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
from proofpath.normalizer import normalize_openvas

_SEVERITY = {
    "log": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class OpenVASItem:
    index: int
    name: str
    target: str
    asset_ip: str | None
    hostname: str | None
    port: int | None
    protocol: str
    service: str | None
    severity: str
    cvss: float | None
    cvss_vector: str | None
    cves: list[str]
    cwes: list[str]
    description: str
    nvt_name: str
    solution: str
    locator: str
    excerpt: str


@dataclass(frozen=True)
class OpenVASImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_items: int


def parse_openvas_xml(raw: bytes) -> tuple[XmlDocument, list[OpenVASItem]]:
    document = parse_xml_evidence(raw, label="OpenVAS")
    root = document.root
    # OpenVAS reports can have <report> as root, or <report><report><results>
    results_parent = root.find(".//results")
    if results_parent is None:
        # Check if root is results directly
        if root.tag == "results":
            results_parent = root
        else:
            results_parent = root.find("results")
    if results_parent is None:
        raise ValueError("OpenVAS XML is missing results element")

    items: list[OpenVASItem] = []
    for item_index, elem in enumerate(results_parent.findall("result"), 1):
        locator = f"//results/result[{item_index}]"
        host_text = _text(elem, "host")
        host_ip: str | None = None
        hostname: str | None = None
        if host_text:
            try:
                host_ip = str(ipaddress.ip_address(host_text.strip()))
            except ValueError:
                hostname = host_text.strip()
                host_ip = None

        port_text = _text(elem, "port")
        port: int | None = None
        protocol = "tcp"
        if port_text:
            parts = port_text.split("/")
            if parts[0].isdigit():
                port = int(parts[0])
            if len(parts) > 1 and parts[1].strip():
                protocol = parts[1].strip().lower()

        name = _text(elem, "name") or "OpenVAS finding"
        threat = _text(elem, "threat").lower()
        severity_val = _SEVERITY.get(threat, "medium")

        cvss_score = _score(_text(elem, "severity"))
        nvt = elem.find("nvt")
        nvt_name = ""
        cves: list[str] = []
        cwes: list[str] = []
        solution = ""
        if nvt is not None:
            nvt_name = _text(nvt, "name")
            if cvss_score is None:
                cvss_score = _score(_text(nvt, "cvss_base"))
            cves = list(dict.fromkeys(_CVE.findall(_text(nvt, "cve"))))
            cwes = list(dict.fromkeys(_CWE.findall(_text(nvt, "cwe"))))
            solution = _text(nvt, "solution")

        description = _text(elem, "description")
        if not cves:
            cves = list(dict.fromkeys(_CVE.findall(description)))
        if not cwes:
            cwes = list(dict.fromkeys(_CWE.findall(description)))

        excerpt = document.excerpt(locator) if locator in document.spans else f"<result id='{elem.get('id', '')}'>{name}</result>"[:300]
        items.append(
            OpenVASItem(
                index=item_index,
                name=name,
                target=host_ip or host_text,
                asset_ip=host_ip,
                hostname=hostname,
                port=port,
                protocol=protocol,
                service=None,
                severity=severity_val,
                cvss=cvss_score,
                cvss_vector=None,
                cves=cves,
                cwes=cwes,
                description=description,
                nvt_name=nvt_name,
                solution=solution,
                locator=locator,
                excerpt=excerpt,
            )
        )
    return document, items


def import_openvas_xml(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> OpenVASImportResult:
    document, items = parse_openvas_xml(raw)
    entry = ledger.store(
        tool="openvas",
        command="import openvas xml",
        content=document.raw,
        status="ok",
        summary=f"Imported OpenVAS XML report with {len(items)} item(s)",
        source_mode="imported",
    )
    findings: list[Finding] = []
    dropped = 0
    for item in items:
        if item.port is None or item.port <= 0:
            dropped += 1
            audit.append(
                "out_of_scope",
                actor,
                {
                    "tool": "openvas",
                    "action_name": ActionName.IMPORT_OPENVAS.value,
                    "target": item.target,
                    "ports": [],
                    "reason": "item has no valid TCP/UDP port",
                    "evidence_id": entry.id,
                    "locator": item.locator,
                    "source_mode": "imported",
                },
            )
            continue
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.IMPORT_OPENVAS,
            target=item.target,
            ports=[item.port],
            arguments={},
            engagement_id=guard.policy.engagement,
            requested_by=actor,
        )
        adapter = OpenVASItemAdapter(item, entry.id, entry.captured_at)
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_OPENVAS: adapter})
        if result.decision.allowed and result.findings:
            findings.extend(result.findings)
        else:
            dropped += 1
            if not result.decision.allowed:
                audit.append(
                    "out_of_scope",
                    actor,
                    {
                        "tool": "openvas",
                        "action_name": action.name.value,
                        "target": action.target,
                        "ports": action.ports,
                        "reason": result.decision.reason,
                        "evidence_id": entry.id,
                        "locator": item.locator,
                        "source_mode": "imported",
                    },
                )
    return OpenVASImportResult(
        evidence_id=entry.id,
        sha256=entry.sha256,
        parsed_items=len(items),
        findings=findings,
        dropped_items=dropped,
    )


class OpenVASItemAdapter:
    def __init__(self, item: OpenVASItem, evidence_id: str, captured_at: datetime) -> None:
        self.item = item
        self.evidence_id = evidence_id
        self.captured_at = captured_at

    def run(
        self,
        decision: GuardDecision,
        guard: ScopeGuard,
        audit: AuditLog,
        ledger: Ledger,
        actor: str,
    ) -> ToolResult:
        if not decision.allowed or decision.tool != "openvas" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified OpenVAS import allow"})
            return ToolResult(status="denied", decision=decision, message="OpenVAS import denied")
        finding = normalize_openvas(self.item, self.evidence_id, self.captured_at)
        if finding is None:
            return ToolResult(status="error", decision=decision, message="OpenVAS item could not be normalized")
        audit.append(
            "openvas_finding_imported",
            actor,
            {
                "action_id": decision.action_id,
                "evidence_id": self.evidence_id,
                "finding_ids": [finding.id],
                "locator": self.item.locator,
                "source_mode": "imported",
            },
        )
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=[finding], message=f"Imported OpenVAS finding {finding.id}")


def _text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else ""


def _score(value: str) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None
