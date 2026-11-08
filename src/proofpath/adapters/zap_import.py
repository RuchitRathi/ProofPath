"""Guarded importer for OWASP ZAP reports (XML or JSON)."""

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
from proofpath.normalizer import normalize_zap

_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}
_CONFIDENCE = {
    "0": "low",
    "1": "low",
    "2": "medium",
    "3": "high",
    "low": "low",
    "medium": "medium",
    "high": "high",
}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class ZapItem:
    index: int
    alert: str
    target: str
    asset_ip: str | None
    hostname: str | None
    port: int
    protocol: str
    service: str
    severity: str
    cvss: float | None
    confidence: str
    cves: list[str]
    cwes: list[str]
    description: str
    uri: str
    param: str
    solution: str
    locator: str
    excerpt: str


@dataclass(frozen=True)
class ZapImportResult:
    evidence_id: str
    sha256: str
    parsed_items: int
    findings: list[Finding]
    dropped_items: int


def parse_zap_report(raw: bytes) -> tuple[str, list[ZapItem]]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("empty OWASP ZAP report")
    items: list[ZapItem] = []
    item_counter = 1

    if text.startswith("{") or text.startswith("["):
        # JSON format
        try:
            data = json.loads(text)
        except Exception as exc:
            raise ValueError("invalid OWASP ZAP JSON") from exc
        sites = data.get("site", []) if isinstance(data, dict) else []
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            host_text = str(site.get("@host") or site.get("host") or "").strip()
            port_val = int(site.get("@port") or site.get("port") or 80)
            asset_ip: str | None = None
            hostname: str | None = None
            try:
                asset_ip = str(ipaddress.ip_address(host_text))
            except ValueError:
                hostname = host_text
            alerts = site.get("alerts", [])
            if isinstance(alerts, dict):
                alerts = [alerts]
            for a in alerts:
                alert_title = str(a.get("alert") or a.get("name") or "ZAP Alert").strip()
                risk_code = str(a.get("riskcode") or a.get("risk") or "1").strip().lower()
                sev = _SEVERITY.get(risk_code, "medium")
                conf_val = _CONFIDENCE.get(str(a.get("confidence") or "2").strip().lower(), "medium")
                desc = str(a.get("desc") or "").strip()
                uri = str(a.get("uri") or "").strip()
                param = str(a.get("param") or "").strip()
                solution = str(a.get("solution") or "").strip()
                cwe_id = str(a.get("cweid") or "").strip()
                cwes: list[str] = [f"CWE-{cwe_id}"] if cwe_id and cwe_id.isdigit() and int(cwe_id) > 0 else []
                cwes.extend(_CWE.findall(desc))
                cves = list(dict.fromkeys(_CVE.findall(desc)))
                locator = f"#/site/alerts/{item_counter}"
                excerpt = f"ZAP alert: {alert_title} [URI: {uri}]"[:300]
                items.append(
                    ZapItem(
                        index=item_counter,
                        alert=alert_title,
                        target=asset_ip or host_text,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=port_val,
                        protocol="tcp",
                        service="https" if port_val in {443, 8443} else "http",
                        severity=sev,
                        cvss=None,
                        confidence=conf_val,
                        cves=cves,
                        cwes=list(dict.fromkeys(cwes)),
                        description=desc,
                        uri=uri,
                        param=param,
                        solution=solution,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    else:
        # XML format
        doc = parse_xml_evidence(raw, label="OWASP ZAP")
        for site_index, site in enumerate(doc.root.findall(".//site"), 1):
            host_text = site.get("host") or ""
            port_val = int(site.get("port") or 80)
            asset_ip = None
            hostname = None
            try:
                asset_ip = str(ipaddress.ip_address(host_text.strip()))
            except ValueError:
                hostname = host_text.strip()
            for alert_index, alert_elem in enumerate(site.findall(".//alertitem"), 1):
                locator = f"//site[{site_index}]//alertitem[{alert_index}]"
                alert_title = _elem_text(alert_elem, "alert") or "ZAP Alert"
                risk_code = _elem_text(alert_elem, "riskcode").lower()
                sev = _SEVERITY.get(risk_code, "medium")
                conf_val = _CONFIDENCE.get(_elem_text(alert_elem, "confidence").lower(), "medium")
                desc = _elem_text(alert_elem, "desc")
                uri = _elem_text(alert_elem, "uri")
                param = _elem_text(alert_elem, "param")
                solution = _elem_text(alert_elem, "solution")
                cwe_id = _elem_text(alert_elem, "cweid")
                cwes = [f"CWE-{cwe_id}"] if cwe_id and cwe_id.isdigit() and int(cwe_id) > 0 else []
                cwes.extend(_CWE.findall(desc))
                cves = list(dict.fromkeys(_CVE.findall(desc)))
                excerpt = doc.excerpt(locator) if locator in doc.spans else f"<alertitem>{alert_title}</alertitem>"[:300]
                items.append(
                    ZapItem(
                        index=item_counter,
                        alert=alert_title,
                        target=asset_ip or host_text,
                        asset_ip=asset_ip,
                        hostname=hostname,
                        port=port_val,
                        protocol="tcp",
                        service="https" if port_val in {443, 8443} else "http",
                        severity=sev,
                        cvss=None,
                        confidence=conf_val,
                        cves=cves,
                        cwes=list(dict.fromkeys(cwes)),
                        description=desc,
                        uri=uri,
                        param=param,
                        solution=solution,
                        locator=locator,
                        excerpt=excerpt,
                    )
                )
                item_counter += 1
    return ("json" if text.startswith("{") or text.startswith("[") else "xml"), items


def import_zap_report(
    raw: bytes,
    guard: ScopeGuard,
    audit: AuditLog,
    ledger: Ledger,
    *,
    actor: str = "analyst",
) -> ZapImportResult:
    fmt, items = parse_zap_report(raw)
    entry = ledger.store(
        tool="zap",
        command=f"import zap {fmt}",
        content=raw,
        status="ok",
        summary=f"Imported OWASP ZAP {fmt.upper()} report with {len(items)} alert(s)",
        source_mode="imported",
    )
    findings: list[Finding] = []
    dropped = 0
    for item in items:
        action = Action(
            id=uuid.uuid4().hex,
            name=ActionName.IMPORT_ZAP,
            target=item.target,
            ports=[item.port],
            arguments={},
            engagement_id=guard.policy.engagement,
            requested_by=actor,
        )
        adapter = ZapItemAdapter(item, entry.id, entry.captured_at)
        result = execute_action(action, guard, audit, ledger, {ActionName.IMPORT_ZAP: adapter})
        if result.decision.allowed and result.findings:
            findings.extend(result.findings)
        else:
            dropped += 1
            if not result.decision.allowed:
                audit.append(
                    "out_of_scope",
                    actor,
                    {
                        "tool": "zap",
                        "action_name": action.name.value,
                        "target": action.target,
                        "ports": action.ports,
                        "reason": result.decision.reason,
                        "evidence_id": entry.id,
                        "locator": item.locator,
                        "source_mode": "imported",
                    },
                )
    return ZapImportResult(
        evidence_id=entry.id,
        sha256=entry.sha256,
        parsed_items=len(items),
        findings=findings,
        dropped_items=dropped,
    )


class ZapItemAdapter:
    def __init__(self, item: ZapItem, evidence_id: str, captured_at: datetime) -> None:
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
        if not decision.allowed or decision.tool != "zap" or not guard.verify_decision(decision):
            audit.append("execution_blocked", actor, {"action_id": decision.action_id, "reason": "decision was not a verified ZAP import allow"})
            return ToolResult(status="denied", decision=decision, message="ZAP import denied")
        finding = normalize_zap(self.item, self.evidence_id, self.captured_at)
        if finding is None:
            return ToolResult(status="error", decision=decision, message="ZAP alert could not be normalized")
        audit.append(
            "zap_finding_imported",
            actor,
            {
                "action_id": decision.action_id,
                "evidence_id": self.evidence_id,
                "finding_ids": [finding.id],
                "locator": self.item.locator,
                "source_mode": "imported",
            },
        )
        return ToolResult(status="ok", decision=decision, evidence_id=self.evidence_id, findings=[finding], message=f"Imported ZAP finding {finding.id}")


def _elem_text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else ""
