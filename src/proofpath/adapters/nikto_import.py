"""Guarded importer for Nikto scan reports (JSON or XML)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import ipaddress
import re
from typing import Any
import uuid
import xml.etree.ElementTree as ET

from proofpath.adapters.base import ToolResult, execute_action
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName, Finding, GuardDecision
from proofpath.scope_guard import ScopeGuard
from proofpath.xml_evidence import parse_xml_evidence
from proofpath.normalizer import normalize_nikto

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class NiktoItem:
    index: int
    title: str
    target: str
    asset_ip: str | None
    hostname: str | None
    port: int
    protocol: str
    service: str
    severity: str
    cvss: float | None
    cves: list[str]
    cwes: list[str]
    message: str
    uri: str
    osvdb: str
    locator: str
    excerpt: str


@dataclass(frozen=True)
class NiktoImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_items: int


def parse_nikto_report(raw: bytes) -> tuple[str, list[NiktoItem]]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("empty Nikto report")
    items: list[NiktoItem] = []
    if text.startswith("{") or text.startswith("["):
        # JSON format
        try:
            data = json.loads(text)
        except Exception as exc:
            raise ValueError("invalid Nikto JSON") from exc
        records = [data] if isinstance(data, dict) else data
        item_counter = 1
        for rec in records:
            host_text = str(rec.get("ip") or rec.get("host") or "").strip()
            port_val = int(rec.get("port", 80))
            asset_ip: str | None = None
            hostname: str | None = None
            try:
                asset_ip = str(ipaddress.ip_address(host_text))
            except ValueError:
                hostname = host_text
            vulns = rec.get("vulnerabilities", [])
            for v in vulns:
                msg = str(v.get("msg") or v.get("description") or "").strip()
                uri = str(v.get("url") or v.get("uri") or "").strip()
                osvdb = str(v.get("OSVDB") or v.get("osvdb") or "").strip()
                cves = list(dict.fromkeys(_CVE.findall(msg)))
                cwes = list(dict.fromkeys(_CWE.findall(msg)))
                # Heuristic severity based on sensitive keywords
                lower_msg = msg.lower()
                sev = "medium"
                if any(w in lower_msg for w in ["remote code", "command execution", "sql injection", "critical"]):
                    sev = "high"
                elif any(w in lower_msg for w in ["information", "header", "banner", "cookie without"]):
                    sev = "low"
                locator = f"#/vulnerabilities/{item_counter}"
                excerpt = f"Nikto issue: {msg} [URI: {uri}]"[:300]
                items.append(
                    NiktoItem(
                        index=item_counter,
                        title=f"Nikto: {uri or msg[:40]}",
                        target=asset_ip or host_text,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=port_val,
                        protocol="tcp",
                        service="https" if port_val in {443, 8443} else "http",
                        severity=sev,
                        cvss=None,
                        cves=cves,
                        cwes=cwes,
                        message=msg,
                        uri=uri,
                        osvdb=osvdb,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    else:
        # XML format
        doc = parse_xml_evidence(raw, label="Nikto")
        scans = doc.root.findall(".//scandetails") or [doc.root]
        item_counter = 1
        for scan in scans:
            target_ip = scan.get("targetip") or scan.get("targethost") or ""
            target_port = int(scan.get("targetport", 80))
            asset_ip = None
            hostname = None
            try:
                asset_ip = str(ipaddress.ip_address(target_ip.strip()))
            except ValueError:
                hostname = target_ip.strip()
            for elem in scan.findall(".//item"):
                locator = f"//item[{item_counter}]"
                desc = _elem_text(elem, "description")
                uri = _elem_text(elem, "uri")
                osvdb = elem.get("osvdbid", "")
                cves = list(dict.fromkeys(_CVE.findall(desc)))
                cwes = list(dict.fromkeys(_CWE.findall(desc)))
                sev = "medium"
                lower_desc = desc.lower()
                if any(w in lower_desc for w in ["remote code", "execution", "sqli", "critical"]):
                    sev = "high"
                elif any(w in lower_desc for w in ["header", "cookie", "banner"]):
                    sev = "low"
                excerpt = doc.excerpt(locator) if locator in doc.spans else f"<item>{desc}</item>"[:300]
                items.append(
                    NiktoItem(
                        index=item_counter,
                        title=f"Nikto: {uri or desc[:40]}",
                        target=asset_ip or target_ip,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=target_port,
                        protocol="tcp",
                        service="https" if target_port in {443, 8443} else "http",
                        severity=sev,
                        cvss=None,
                        cves=cves,
                        cwes=cwes,
                        message=desc,
                        uri=uri,
                        osvdb=osvdb,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    return ("json" if text.startswith("{") or text.startswith("[") else "xml"), items


def import_nikto_report(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> NiktoImportResult:
    fmt, items = parse_nikto_report(raw)
    entry = ledger.store(
        tool="nikto",
        command=f"import nikto {fmt}",
        content=raw,
        status="ok",
        summary=f"Imported Nikto {fmt.upper()} report with {len(items)} item(s)",
        source_mode="imported",
    )
    findings: list[Finding] = []
    dropped = 0
    for item in items:
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.IMPORT_NIKTO,
            target=item.target,
            ports=[item.port],
            arguments={},
            engagement_id=guard.policy.engagement,
            requested_by=actor,
        )
        adapter = NiktoItemAdapter(item, entry.id, entry.captured_at)
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_NIKTO: adapter})
        if result.decision.allowed and result.findings:
            findings.extend(result.findings)
        else:
            dropped += 1
            if not result.decision.allowed:
                audit.append(
                    "out_of_scope",
                    actor,
                    {
                        "tool": "nikto",
                        "action_name": action.name.value,
                        "target": action.target,
                        "ports": action.ports,
                        "reason": result.decision.reason,
                        "evidence_id": entry.id,
                        "locator": item.locator,
                        "source_mode": "imported",
                    },
                )
    return NiktoImportResult(
        evidence_id=entry.id,
        sha256=entry.sha256,
        parsed_items=len(items),
        findings=findings,
        dropped_items=dropped,
    )


class NiktoItemAdapter:
    def __init__(self, item: NiktoItem, evidence_id: str, captured_at: datetime) -> None:
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
        if not decision.allowed or decision.tool != "nikto" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified Nikto import allow"})
            return ToolResult(status="denied", decision=decision, message="Nikto import denied")
        finding = normalize_nikto(self.item, self.evidence_id, self.captured_at)
        if finding is None:
            return ToolResult(status="error", decision=decision, message="Nikto item could not be normalized")
        audit.append(
            "nikto_finding_imported",
            actor,
            {
                "action_id": decision.action_id,
                "evidence_id": self.evidence_id,
                "finding_ids": [finding.id],
                "locator": self.item.locator,
                "source_mode": "imported",
            },
        )
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=[finding], message=f"Imported Nikto finding {finding.id}")


def _elem_text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else ""
