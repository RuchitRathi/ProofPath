"""Guarded importer for Metasploit findings and lab validation records."""

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
from proofpath.normalizer import normalize_metasploit

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class MetasploitItem:
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
    info: str
    validated: bool
    locator: str
    excerpt: str


@dataclass(frozen=True)
class MetasploitImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_items: int


def parse_metasploit_report(raw: bytes) -> tuple[str, list[MetasploitItem]]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("empty Metasploit report")
    items: list[MetasploitItem] = []
    item_counter = 1

    if text.startswith("{") or text.startswith("["):
        # JSON format
        try:
            data = json.loads(text)
        except Exception as exc:
            raise ValueError("invalid Metasploit JSON") from exc
        hosts = data.get("hosts", []) if isinstance(data, dict) else data
        for host_rec in hosts:
            addr = str(host_rec.get("address") or host_rec.get("ip") or host_rec.get("host") or "").strip()
            asset_ip = None
            hostname = None
            try:
                asset_ip = str(ipaddress.ip_address(addr))
            except ValueError:
                hostname = addr
            vulns = host_rec.get("vulns", [])
            for v in vulns:
                title = str(v.get("name") or "Metasploit finding").strip()
                info = str(v.get("info") or "").strip()
                port = int(v.get("port") or 80)
                proto = str(v.get("proto") or "tcp").lower()
                refs = v.get("refs", [])
                if isinstance(refs, str):
                    refs = [refs]
                cves = list(dict.fromkeys(_CVE.findall(" ".join(refs) + " " + info)))
                cwes = list(dict.fromkeys(_CWE.findall(" ".join(refs) + " " + info)))
                validated = bool(v.get("validated") or "validated" in info.lower() or "proof" in info.lower())
                locator = f"#/hosts/vulns/{item_counter}"
                excerpt = f"Metasploit record: {title} [Port: {port}]"[:300]
                items.append(
                    MetasploitItem(
                        index=item_counter,
                        title=title,
                        target=asset_ip or addr,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=port,
                        protocol=proto,
                        service=str(v.get("service") or "unknown"),
                        severity="high" if validated else "medium",
                        cvss=None,
                        cves=cves,
                        cwes=cwes,
                        info=info,
                        validated=validated,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    else:
        # XML format
        doc = parse_xml_evidence(raw, label="Metasploit")
        for host_elem in doc.root.findall(".//host"):
            addr = _elem_text(host_elem, "address")
            asset_ip = None
            hostname = None
            try:
                asset_ip = str(ipaddress.ip_address(addr))
            except ValueError:
                hostname = addr
            # Check default port from services if any
            default_port = 80
            svc_elem = host_elem.find(".//service")
            if svc_elem is not None:
                p_text = _elem_text(svc_elem, "port")
                if p_text.isdigit():
                    default_port = int(p_text)
            for vuln_elem in host_elem.findall(".//vuln"):
                locator = f"//host//vuln[{item_counter}]"
                title = _elem_text(vuln_elem, "name") or "Metasploit finding"
                info = _elem_text(vuln_elem, "info")
                refs_text = " ".join(elem.text or "" for elem in vuln_elem.findall(".//ref"))
                cves = list(dict.fromkeys(_CVE.findall(refs_text + " " + info)))
                cwes = list(dict.fromkeys(_CWE.findall(refs_text + " " + info)))
                validated = "validated" in info.lower() or "proof" in info.lower()
                excerpt = doc.excerpt(locator) if locator in doc.spans else f"<vuln>{title}</vuln>"[:300]
                items.append(
                    MetasploitItem(
                        index=item_counter,
                        title=title,
                        target=asset_ip or addr,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=default_port,
                        protocol="tcp",
                        service="unknown",
                        severity="high" if validated else "medium",
                        cvss=None,
                        cves=cves,
                        cwes=cwes,
                        info=info,
                        validated=validated,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    return ("json" if text.startswith("{") or text.startswith("[") else "xml"), items


def import_metasploit_report(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> MetasploitImportResult:
    fmt, items = parse_metasploit_report(raw)
    entry = ledger.store(
        tool="metasploit",
        command=f"import metasploit {fmt}",
        content=raw,
        status="ok",
        summary=f"Imported Metasploit {fmt.upper()} report with {len(items)} record(s)",
        source_mode="imported",
    )
    findings: list[Finding] = []
    dropped = 0
    for item in items:
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.IMPORT_METASPLOIT,
            target=item.target,
            ports=[item.port],
            arguments={},
            engagement_id=guard.policy.engagement,
            requested_by=actor,
        )
        adapter = MetasploitItemAdapter(item, entry.id, entry.captured_at)
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_METASPLOIT: adapter})
        if result.decision.allowed and result.findings:
            findings.extend(result.findings)
        else:
            dropped += 1
            if not result.decision.allowed:
                audit.append(
                    "out_of_scope",
                    actor,
                    {
                        "tool": "metasploit",
                        "action_name": action.name.value,
                        "target": action.target,
                        "ports": action.ports,
                        "reason": result.decision.reason,
                        "evidence_id": entry.id,
                        "locator": item.locator,
                        "source_mode": "imported",
                    },
                )
    return MetasploitImportResult(
        evidence_id=entry.id,
        sha256=entry.sha256,
        parsed_items=len(items),
        findings=findings,
        dropped_items=dropped,
    )


class MetasploitItemAdapter:
    def __init__(self, item: MetasploitItem, evidence_id: str, captured_at: datetime) -> None:
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
        if not decision.allowed or decision.tool != "metasploit" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified Metasploit import allow"})
            return ToolResult(status="denied", decision=decision, message="Metasploit import denied")
        finding = normalize_metasploit(self.item, self.evidence_id, self.captured_at)
        if finding is None:
            return ToolResult(status="error", decision=decision, message="Metasploit finding could not be normalized")
        audit.append(
            "metasploit_finding_imported",
            actor,
            {
                "action_id": decision.action_id,
                "evidence_id": self.evidence_id,
                "finding_ids": [finding.id],
                "locator": self.item.locator,
                "source_mode": "imported",
            },
        )
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=[finding], message=f"Imported Metasploit finding {finding.id}")


def _elem_text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else ""
