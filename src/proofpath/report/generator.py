"""Grounded, deterministic ReportLab PDF reports with evidence and audit links."""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from proofpath.audit import AuditLog
from proofpath.grounding import verify_finding
from proofpath.ledger import Ledger
from proofpath.risk import rank_findings
from proofpath.schemas import Finding, ServiceObservation


SEVERITIES = ("critical", "high", "medium", "low", "info", "not_provided")


def generate_pdf(
    findings: list[Finding],
    observations: list[ServiceObservation],
    ledger: Ledger,
    audit: AuditLog,
    output_path: str | Path,
    *,
    engagement: str,
    scope_cidrs: list[str],
    criticality: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create the template report, validating every finding before rendering."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    grounded: list[Finding] = []
    for finding in findings:
        result = verify_finding(finding, ledger, audit)
        if result.accepted:
            grounded.append(finding)
    ranked = rank_findings(findings, observations, criticality)  # show rejected items with fallback evidence-only labels
    evidence_ids = sorted({ref.evidence_id for finding in findings for ref in finding.evidence})
    evidence_records = {item: ledger.load(item) for item in evidence_ids}
    evidence_hashes = {item: evidence_records[item].sha256 for item in evidence_ids}
    entries_before = audit.read_entries()
    prior_chain_head = entries_before[-1].entry_hash if entries_before else "0" * 64
    timestamp = datetime.now(timezone.utc).isoformat()
    integration_rows = _integration_rows()
    severity_counts = {severity: sum(item.severity == severity for item in findings) for severity in SEVERITIES}
    failures = [entry for entry in entries_before if entry.event_type in {"tool_error", "nmap_result"} and entry.details.get("status") in {"error", "timeout", "tool_not_found"}]
    approvals = [entry for entry in entries_before if entry.event_type in {"approval_requested", "approval_decision", "active_validation_outcome"}]
    imported = any(item.source_mode == "imported" for item in evidence_records.values())
    synthetic = any(
        "synthetic" in item.summary.casefold()
        or b"synthetic" in ledger.read_bytes(item.id).lower()
        for item in evidence_records.values()
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
    story: list[Any] = [Paragraph("ProofPath Security Assessment", styles["Title"]), Paragraph(f"Engagement: {_esc(engagement)} · Generated: {_esc(timestamp)}", styles["Normal"]), Spacer(1, 5 * mm)]

    _heading(story, "7.1 Executive summary and scope", styles)
    top = ", ".join(f"{row.finding.id} ({row.finding.severity})" for row in ranked[:3]) or "None"
    overall = f"{len(findings)} reported finding(s) are present; no system-wide safe/unsafe verdict is inferred." if findings else "No findings are recorded; no system-wide safe/unsafe verdict is inferred."
    summary = f"{len(findings)} finding(s); {sum(bool(f.cves) for f in findings)} with reported CVE identifiers. Top prioritized findings: {top}. Overall assessment: {overall} Assessment scope: {', '.join(scope_cidrs) or 'not provided'}. This report reflects only cited ledger records and configured integration status."
    story.append(Paragraph(_esc(summary), styles["BodyText"]))

    _heading(story, "7.2 Methodology", styles)
    story.append(Paragraph("Rules of engagement: targets and ports are checked against the engagement scope. Active validation is limited to a separately approved GET/HEAD request on an allowlisted path. No exploit payloads are sent.", styles["BodyText"]))
    assets_tested = sorted({f.asset.ip for f in findings} | {row.ip for row in observations})
    story.append(Paragraph("Assets represented in observations or findings: " + _esc(", ".join(assets_tested) or "none"), styles["BodyText"]))
    story.append(Paragraph("Tool execution summary and status matrix:", styles["BodyText"]))
    matrix = [["Tool", "Status", "Execution/source note"]]
    matrix.extend([[row["tool"], row["mode"], row["limitation"]] for row in integration_rows])
    for ev in evidence_records.values():
        matrix.append([ev.tool, "Live" if ev.source_mode == "live" else "Import-only", ("imported, not live-executed; " if ev.source_mode == "imported" else "live evidence; ") + ev.summary])
    story.append(_table(matrix, [35 * mm, 23 * mm, 125 * mm], styles))

    _heading(story, "7.3 Severity distribution and prioritized findings", styles)
    story.append(_severity_chart(severity_counts))
    risk_rows = [["Rank", "ID", "Severity/CVSS", "Status", "Score", "Factor breakdown (value · source · weight)"]]
    for row in ranked:
        cvss = f"{row.finding.severity} / {row.finding.cvss:.1f}" if row.finding.cvss is not None else f"{row.finding.severity} / not provided"
        factors = "; ".join(f"{f.name}: {f.value} · {f.source} · {f.weight:.0%}" for f in row.factors)
        risk_rows.append([str(row.rank), row.finding.id, cvss, row.status_label, str(row.priority_score) if row.priority_score is not None else "not scored", factors])
    story.append(_table(risk_rows, [12 * mm, 22 * mm, 30 * mm, 25 * mm, 18 * mm, 78 * mm], styles, wide=True))

    _heading(story, "7.4 Detailed findings", styles)
    for index, finding in enumerate(findings, 1):
        grounding = "grounded" if finding in grounded else "AI inference omitted; evidence-only template fallback"
        story.append(Paragraph(f"<b>{index}. {_esc(finding.id)} — {_esc(finding.title)}</b>", styles["Heading3"]))
        story.append(Paragraph(f"Asset: {_esc(finding.asset.ip)} · Port: {finding.port}/{_esc(finding.protocol)} · Severity/CVSS: {_esc(finding.severity)} / {_esc(f'{finding.cvss:.1f}' if finding.cvss is not None else 'not provided')} · CVE: {_esc(', '.join(finding.cves) or 'not provided')} · CWE: {_esc(', '.join(finding.cwes) or 'not provided')}", styles["BodyText"]))
        story.append(Paragraph(f"Observed: {_esc(finding.observed)}", styles["BodyText"]))
        if finding.inference and finding in grounded:
            story.append(Paragraph("AI inference: " + _esc(finding.inference), styles["BodyText"]))
        story.append(Paragraph(f"Confidence: {_esc(finding.confidence)} · Status: {_esc(finding.status)} · Validation: {_esc(finding.validation_status)} · Grounding: {grounding}", styles["BodyText"]))
        for ref in finding.evidence:
            story.append(Paragraph(f"Evidence {_esc(ref.evidence_id)} · locator {_esc(ref.locator)} · verbatim excerpt: {_esc(ref.excerpt)}", styles["Small"]))

    _heading(story, "7.5 Impact and remediation", styles)
    story.append(Paragraph("Impact is limited to the tool-reported finding details and observations above. Remediation text is included only when supplied by an imported tool; otherwise use generic guidance to review the affected service configuration and vendor-supported fixes. Standards references are shown as mapped to only when present in the source finding.", styles["BodyText"]))
    for finding in findings:
        refs = ", ".join(finding.mapped_to) or "no standards mapping provided"
        story.append(Paragraph(f"{_esc(finding.id)} — standards mapped to: {_esc(refs)}", styles["Small"]))

    _heading(story, "7.6 Assessment limitations", styles)
    limitations = ["This report uses synthetic data." if synthetic else "This report uses imported records." if imported else "No imported or synthetic source label was present.", "No external host was contacted during PDF generation.", f"Assessment timestamp: {_esc(timestamp)}."]
    limitations.extend(f"Approval audit: {entry.event_type} by {entry.actor} at {entry.timestamp}; {entry.details}" for entry in approvals)
    limitations.extend(f"Recorded scan failure: {entry.event_type} {entry.details}" for entry in failures)
    limitations.extend(f"Finding {f.id}: status {f.status}." for f in findings if f.status in {"refuted", "false_positive_candidate"})
    story.extend(Paragraph(_esc(line), styles["Small"]) for line in limitations)

    story.append(PageBreak())
    _heading(story, "Appendix A: evidence index", styles)
    evidence_rows = [["Evidence ID", "Tool", "Source mode", "SHA-256", "Captured at", "Artifact filename"]]
    evidence_rows.extend([[ev.id, ev.tool, ev.source_mode, ev.sha256, ev.captured_at.isoformat(), Path(ev.artifact_path).name] for ev in evidence_records.values()])
    story.append(_table(evidence_rows, [23 * mm, 22 * mm, 22 * mm, 43 * mm, 35 * mm, 30 * mm], styles, wide=True))
    _heading(story, "Appendix B: integration status matrix", styles)
    story.append(_table([["Tool", "Status", "Limitation"], *[[r["tool"], r["mode"], r["limitation"]] for r in integration_rows]], [35 * mm, 23 * mm, 125 * mm], styles))
    _heading(story, "Appendix C: audit and report hashes", styles)
    story.append(Paragraph(f"Audit chain head before report generation: {prior_chain_head}", styles["Small"]))
    story.append(Paragraph("The PDF SHA-256 is recorded in the chained report_generated audit event after this file is written.", styles["Small"]))

    doc = SimpleDocTemplate(str(out), pagesize=landscape(A4), title="ProofPath Security Assessment", author="ProofPath", topMargin=14 * mm, bottomMargin=14 * mm)
    doc.build(story)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (out.parent / "current-findings.json").write_text(json.dumps([item.model_dump(mode="json") for item in findings], indent=2), encoding="utf-8")
    audit.append("report_generated", "analyst", {
        "report_path": str(out.resolve()), "report_sha256": digest, "finding_ids": [f.id for f in findings],
        "evidence_ids": evidence_ids, "evidence_hashes": evidence_hashes, "source_label": "synthetic" if synthetic else "imported" if imported else "live",
        "audit_chain_head_in_report": prior_chain_head,
    })
    return {"path": str(out), "sha256": digest, "evidence_ids": evidence_ids, "grounded_findings": len(grounded), "total_findings": len(findings), "severity_counts": severity_counts}


def _heading(story: list[Any], text: str, styles: Any) -> None:
    story.append(Paragraph(_esc(text), styles["Heading2"]))


def _table(rows: list[list[str]], widths: list[float], styles: Any, wide: bool = False) -> Table:
    data = [[Paragraph(_esc(str(cell)), styles["Cell"]) for cell in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#23364d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#aab4c0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _severity_chart(counts: dict[str, int]) -> Drawing:
    drawing = Drawing(440, 170)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.height, chart.width = 42, 30, 120, 370
    labels = list(SEVERITIES)
    chart.data = [[counts[label] for label in labels]]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.angle = 20
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(1, max(counts.values(), default=0))
    chart.valueAxis.valueStep = 1
    chart.bars[0].fillColor = colors.HexColor("#4472c4")
    drawing.add(chart)
    return drawing


def _integration_rows() -> list[dict[str, str]]:
    from proofpath.integrations import INTEGRATIONS
    return INTEGRATIONS


def _esc(value: str) -> str:
    return html.escape(str(value), quote=True).replace("\n", " ")
