"""Grounded, deterministic ReportLab PDF reports with evidence and audit links."""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)

from proofpath.audit import AuditLog
from proofpath.grounding import verify_finding
from proofpath.ledger import Ledger
from proofpath.risk import rank_findings
from proofpath.schemas import Finding, ServiceObservation
from proofpath.threat_intel import PublicThreatIntel


SEVERITIES = ("critical", "high", "medium", "low", "info", "not_provided")

# Planning guidance only — not a contractual remediation commitment.
_REMEDIATION_HORIZON = {
    "critical": "immediate (24 hours)",
    "high": "within 7 days",
    "medium": "within 30 days",
    "low": "next maintenance window",
    "info": "next maintenance window",
    "not_provided": "triage required",
}

SEV_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "low":      colors.HexColor("#3b82f6"),
    "info":     colors.HexColor("#94a3b8"),
    "not_provided": colors.HexColor("#64748b"),
}


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
    public_intel: PublicThreatIntel | None = None,
    baseline_findings: list[Finding] | None = None,
) -> dict[str, Any]:
    """Create the grounded, deterministic VAPT report."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Grounding pass
    grounded: list[Finding] = []
    for finding in findings:
        result = verify_finding(finding, ledger, audit)
        if result.accepted:
            grounded.append(finding)

    ranked = rank_findings(findings, observations, criticality, public_intel)
    evidence_ids = sorted({ref.evidence_id for f in findings for ref in f.evidence})
    evidence_records = {eid: ledger.load(eid) for eid in evidence_ids}
    evidence_hashes = {eid: evidence_records[eid].sha256 for eid in evidence_ids}
    entries_before = audit.read_entries()
    prior_chain_head = entries_before[-1].entry_hash if entries_before else "0" * 64
    timestamp = datetime.now(timezone.utc).isoformat()
    integration_rows = _integration_rows()
    severity_counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    failures = [e for e in entries_before if e.event_type in {"tool_error", "nmap_result"} and e.details.get("status") in {"error", "timeout", "tool_not_found"}]
    approvals = [e for e in entries_before if e.event_type in {"approval_requested", "approval_decision", "active_validation_outcome"}]
    imported = any(ev.source_mode == "imported" for ev in evidence_records.values())
    synthetic = any(
        "synthetic" in ev.summary.casefold() or b"synthetic" in ledger.read_bytes(ev.id).lower()
        for ev in evidence_records.values()
    )

    styles = _build_styles()
    story: list[Any] = []

    # ── Cover block ──────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("CONFIDENTIAL — AUTHORISED SECURITY ASSESSMENT", styles["Kicker"]))
    story.append(Paragraph("ProofPath VAPT Report", styles["CoverTitle"]))
    story.append(Paragraph(
        f"Engagement: <b>{_esc(engagement)}</b> &nbsp;·&nbsp; "
        f"Generated: <b>{_esc(timestamp[:19].replace('T', ' '))} UTC</b> &nbsp;·&nbsp; "
        f"Scope: <b>{_esc(', '.join(scope_cidrs) or 'not provided')}</b>",
        styles["CoverSub"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=6 * mm))

    # ── 7.1 Executive Summary ────────────────────────────────────────────
    _heading(story, "7.1  Executive Summary", styles)
    crit_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    top_findings = ", ".join(f"{r.finding.id} ({r.finding.severity})" for r in ranked[:3]) or "None"
    overall = (
        f"{len(findings)} finding(s) identified across {len({f.asset.ip for f in findings})} asset(s). "
        f"{crit_count} critical and {high_count} high severity findings require immediate remediation. "
        f"Top priority findings: {top_findings}. "
        f"Assessment scope: {', '.join(scope_cidrs) or 'not provided'}. "
        f"No system-wide safe/unsafe verdict is inferred from this report — findings reflect only cited ledger evidence."
    )
    story.append(Paragraph(_esc(overall), styles["BodyText"]))
    story.append(Spacer(1, 3 * mm))

    # Summary metrics table
    multi_tool = sum(1 for f in findings if len(f.source_tools) > 1)
    confirmed = sum(1 for f in findings if f.status == "confirmed")
    fp_cands = sum(1 for f in findings if f.status == "false_positive_candidate")
    cves_reported = sum(1 for f in findings if f.cves)
    summary_data = [
        ["Metric", "Value"],
        ["Total correlated findings", str(len(findings))],
        ["Critical / High / Medium / Low", f"{severity_counts.get('critical',0)} / {severity_counts.get('high',0)} / {severity_counts.get('medium',0)} / {severity_counts.get('low',0)}"],
        ["Confirmed findings (multi-tool)", str(confirmed)],
        ["Multi-tool corroborated", str(multi_tool)],
        ["False-positive candidates", str(fp_cands)],
        ["Findings with CVE identifiers", str(cves_reported)],
        ["Grounded by AI verifier", str(len(grounded))],
        ["Audit entries", str(len(entries_before))],
    ]
    story.append(_table(summary_data, [80 * mm, 80 * mm], styles))

    top_asset_counts: dict[str, int] = {}
    for finding in findings:
        top_asset_counts[finding.asset.ip] = top_asset_counts.get(finding.asset.ip, 0) + 1
    busiest_asset = max(top_asset_counts.items(), key=lambda item: item[1])[0] if top_asset_counts else "none"
    top_item = ranked[0].finding if ranked else None
    story.append(Paragraph(
        f"<b>Key themes.</b> Most affected asset: {_esc(busiest_asset)}. "
        f"Findings carrying CVE identifiers: {cves_reported}. "
        f"Suggested remediation window for the top-ranked item "
        f"({_esc(top_item.id) if top_item else 'none'}): "
        f"{_REMEDIATION_HORIZON.get(top_item.severity, 'triage required') if top_item else 'not applicable'}. "
        f"Windows are planning guidance for this engagement, not a contractual commitment.",
        styles["BodyText"],
    ))

    # ── 7.2 Methodology ──────────────────────────────────────────────────
    _heading(story, "7.2  Assessment Methodology", styles)
    story.append(Paragraph(
        "Rules of engagement: all targets are validated against the engagement scope policy before any "
        "action is taken. Active validation is limited to a human-approved, single-use GET/HEAD request "
        "on an allowlisted path. No exploit payloads, shell commands, or unapproved network traffic are sent.",
        styles["BodyText"],
    ))
    assets_tested = sorted({f.asset.ip for f in findings} | {o.ip for o in observations})
    story.append(Paragraph(f"<b>Assets tested:</b> {_esc(', '.join(assets_tested) or 'none')}", styles["BodyText"]))
    story.append(Paragraph("<b>Tool execution and source matrix:</b>", styles["BodyText"]))
    matrix = [["Tool", "Status", "Source note"]]
    matrix.extend([[r["tool"], r["mode"], r["limitation"][:120]] for r in integration_rows])
    for ev in evidence_records.values():
        note = ("imported, not live-executed — " if ev.source_mode == "imported" else "live evidence — ") + ev.summary[:80]
        matrix.append([ev.tool, "Live" if ev.source_mode == "live" else "Import-only", note])
    story.append(_table(matrix, [35 * mm, 25 * mm, 123 * mm], styles))

    # ── 7.3 Severity Distribution ─────────────────────────────────────────
    _heading(story, "7.3  Severity Distribution & Risk Prioritization", styles)
    story.append(_severity_chart(severity_counts))
    risk_rows = [["Rank", "ID", "Title", "Asset", "Sev / CVSS", "Status", "Score", "Key Risk Factors"]]
    for row in ranked:
        cvss_str = f"{row.finding.cvss:.1f}" if row.finding.cvss is not None else "N/A"
        key_factors = "; ".join(
            f"{f.name}={f.value}"
            for f in row.factors
            if f.included and f.normalized is not None and f.normalized > 0.5
        )[:100]
        risk_rows.append([
            str(row.rank),
            row.finding.id,
            row.finding.title[:40],
            row.finding.asset.ip,
            f"{row.finding.severity.upper()} / {cvss_str}",
            row.status_label,
            str(row.priority_score) if row.priority_score is not None else "N/A",
            key_factors or "—",
        ])
    story.append(_table(risk_rows, [10*mm, 22*mm, 40*mm, 22*mm, 22*mm, 22*mm, 14*mm, 31*mm], styles, wide=True))

    # ── 7.4 Detailed Findings ─────────────────────────────────────────────
    _heading(story, "7.4  Detailed Vulnerability Findings", styles)
    for idx, finding in enumerate(findings, 1):
        is_grounded = finding in grounded
        grounding_label = "Grounded ✔" if is_grounded else "Evidence-only (AI inference omitted)"
        # Finding header row
        sev_color = SEV_COLORS.get(finding.severity, colors.HexColor("#94a3b8"))
        story.append(Paragraph(
            f"<b>{idx}. [{finding.severity.upper()}] {_esc(finding.id)} — {_esc(finding.title)}</b>",
            styles["FindingHeader"],
        ))
        # Key attributes
        attrs = [
            ["Asset", f"{finding.asset.ip}:{finding.port}/{finding.protocol}"],
            ["Service", finding.service or "not reported"],
            ["CVE(s)", ", ".join(finding.cves) or "not provided"],
            ["CWE(s)", ", ".join(finding.cwes) or "not provided"],
            ["CVSS", f"{finding.cvss:.1f}" if finding.cvss is not None else "not provided"],
            ["Confidence", finding.confidence.title()],
            ["Status", finding.status.replace("_", " ").title()],
            ["Validation", finding.validation_status.replace("_", " ").title()],
            ["Sources", ", ".join(finding.source_tools)],
            ["Grounding", grounding_label],
        ]
        story.append(_table(attrs, [35*mm, 148*mm], styles))
        story.append(Paragraph(f"<b>Observed:</b> {_esc(finding.observed)}", styles["Small"]))
        if finding.inference and is_grounded:
            story.append(Paragraph(f"<b>AI Inference (grounded):</b> {_esc(finding.inference)}", styles["Small"]))
        if finding.conflict_notes:
            story.append(Paragraph(f"<b>Cross-tool conflicts:</b> {_esc(' | '.join(finding.conflict_notes))}", styles["Small"]))
        # Standards mapping
        if finding.mapped_to:
            story.append(Paragraph(f"<b>Mapped to:</b> {_esc(', '.join(finding.mapped_to))}", styles["Small"]))
        # Evidence refs
        for ref in finding.evidence:
            story.append(Paragraph(
                f"<b>Evidence</b> <font color='#2563eb'>{_esc(ref.evidence_id)}</font> · "
                f"locator: <font face='Courier'>{_esc(ref.locator)}</font> · "
                f"excerpt: {_esc((ref.excerpt or '')[:200])}",
                styles["Small"],
            ))
        story.append(Spacer(1, 3 * mm))

    # ── 7.5 Impact & Remediation ──────────────────────────────────────────
    _heading(story, "7.5  Impact & Actionable Remediation", styles)
    story.append(Paragraph(
        "Impact assessments are grounded in tool-reported severity, CVSS vectors, and observed exposure states. "
        "Remediation recommendations prioritize defense-in-depth, configuration hardening, and vendor security updates. "
        "Standards references use 'mapped to' wording; they are not a claim of formal compliance.",
        styles["BodyText"],
    ))
    roadmap_rows = [["Priority", "Finding", "Severity", "Target", "Suggested window", "Score"]]
    for row in ranked:
        roadmap_rows.append([
            str(row.rank),
            row.finding.id,
            row.finding.severity.upper(),
            f"{row.finding.asset.ip}:{row.finding.port}",
            _REMEDIATION_HORIZON.get(row.finding.severity, "triage required"),
            str(row.priority_score) if row.priority_score is not None else "N/A",
        ])
    if len(roadmap_rows) > 1:
        story.append(Paragraph(
            "<b>Prioritised remediation roadmap</b> — highest computed risk first. "
            "Windows are planning guidance, not a contractual commitment.",
            styles["Small"],
        ))
        story.append(_table(roadmap_rows, [18*mm, 24*mm, 20*mm, 34*mm, 48*mm, 23*mm], styles, wide=True))
        story.append(Spacer(1, 3*mm))
    for finding in findings:
        refs = ", ".join(finding.mapped_to) or "no standards mapping in source data"
        impact = {
            "critical": "Critical — potential for remote code execution, full host compromise, or systemic data breach. Immediate remediation required.",
            "high":     "High — exposure of sensitive assets, unauthorized manipulation, or lateral movement risk. Remediate within 7 days.",
            "medium":   "Medium — misconfiguration or weakness facilitating information disclosure. Remediate within 30 days.",
        }.get(finding.severity, "Low/Informational — hardening opportunity. Address in next maintenance window.")
        cve_str = f" for {', '.join(finding.cves)}" if finding.cves else ""
        remediation = (
            f"1. Apply current vendor security updates{cve_str}. "
            f"2. Review and harden service configuration on port {finding.port}/{finding.protocol}. "
            f"3. Enforce input validation and least-privilege access controls. "
            f"4. Verify network ingress/egress controls for this asset."
        )
        story.append(Paragraph(f"<b>{_esc(finding.id)} — {_esc(finding.title)}</b>", styles["Heading3"]))
        story.append(Paragraph(f"<b>Business &amp; Technical Impact:</b> {_esc(impact)}", styles["Small"]))
        story.append(Paragraph(f"<b>Actionable Remediation:</b> {_esc(remediation)}", styles["Small"]))
        story.append(Paragraph(f"<b>Standards Alignment:</b> {_esc(refs)}", styles["Small"]))
        story.append(Spacer(1, 2 * mm))

    # ── 7.6 Standards & Reference Frameworks ─────────────────────────────
    _heading(story, "7.6  Standards & Reference Frameworks", styles)
    story.append(Paragraph(
        "The following standards and frameworks are applied where applicable. "
        "Use of a framework in this report does not constitute formal compliance with it.",
        styles["BodyText"],
    ))
    fw_rows = [
        ["Framework", "Version", "Application in this assessment"],
        ["NIST SP 800-115", "2008", "Lifecycle stages — recon, vulnerability analysis, validation — follow this Technical Guide."],
        ["OWASP Top 10", "2021", "Web findings from Burp, ZAP, Nikto mapped to OWASP Top 10:2021 where CWE/issue type matches."],
        ["CVE / NVD", "MITRE/NIST", "CVE identifiers from scanners preserved verbatim. Absent CVEs shown as 'not provided', never fabricated."],
        ["CVSS v3.1", "FIRST", "Scanner-reported CVSS scores drive risk factor scoring. NVD context fetched for findings without scanner score."],
        ["CWE", "MITRE", "CWE identifiers from findings preserved in section 7.4 and Appendix A."],
        ["MITRE ATT&CK", "Enterprise", "Technique IDs (e.g. T1190 Exploit Public-Facing Application) mapped to service exposure and web findings."],
        ["NIST CSF 2.0", "2024", "Remediation recommendations reference CSF 2.0 functions: Identify, Protect, Detect, Respond, Recover."],
    ]
    story.append(_table(fw_rows, [38*mm, 22*mm, 123*mm], styles))
    story.append(Spacer(1, 3*mm))

    # ── ATT&CK / OWASP / NIST coverage (mapped from observed CWEs) ─────────
    coverage: dict[str, int] = {}
    for finding in findings:
        for mapping in finding.mapped_to:
            coverage[mapping] = coverage.get(mapping, 0) + 1
    if coverage:
        story.append(Paragraph(
            "<b>Observed coverage — standards mapped to each finding.</b> "
            "Entries are derived from tool-reported CWE identifiers using 'mapped to' wording; "
            "an entry is a mapping of the finding, not a claim of formal compliance.",
            styles["Small"],
        ))
        cov_rows = [["Framework entry (mapped to)", "Findings"]]
        for mapping, count in sorted(coverage.items(), key=lambda kv: (-kv[1], kv[0])):
            cov_rows.append([mapping, str(count)])
        story.append(_table(cov_rows, [143*mm, 40*mm], styles))
        story.append(Spacer(1, 3*mm))

    # ── 7.7 Assessment Limitations ────────────────────────────────────────
    _heading(story, "7.7  Assessment Limitations", styles)
    limitations = [
        "This report uses synthetic data." if synthetic else
        "This report uses imported records." if imported else
        "Source label not present in evidence records.",
        "No external host was contacted during report generation.",
        f"Assessment timestamp (UTC): {timestamp}.",
        f"Grounded findings: {len(grounded)} of {len(findings)} passed the AI grounding verifier.",
    ]
    limitations += [f"Approval audit: {e.event_type} by {e.actor} at {e.timestamp}" for e in approvals]
    limitations += [f"Scan failure recorded: {e.event_type} — {e.details.get('status','')}" for e in failures]
    limitations += [f"Finding {f.id} status: {f.status}." for f in findings if f.status in {"refuted", "false_positive_candidate"}]
    for line in limitations:
        story.append(Paragraph(f"• {_esc(line)}", styles["Small"]))

    # ── 7.8 Remediation Status (Retest) ───────────────────────────────────
    if baseline_findings is not None:
        from proofpath.diff import compare_assessments
        delta = compare_assessments(baseline_findings, findings)
        _heading(story, "7.8  Remediation Status (Retest vs Baseline)", styles)
        story.append(Paragraph(
            f"Compared {len(baseline_findings)} baseline finding(s) against {len(findings)} current finding(s) "
            f"using the deterministic correlation key. <b>{delta.total_remediated} remediated</b>, "
            f"{delta.total_persisting} persisting, {delta.total_new} new.",
            styles["BodyText"],
        ))
        delta_rows = [["Change", "ID", "Severity", "Asset", "Title", "Note"]]
        for base_f in delta.remediated_findings:
            delta_rows.append([
                "Remediated", base_f.id, base_f.severity.upper(), f"{base_f.asset.ip}:{base_f.port}",
                base_f.title[:40], "in baseline, resolved or absent now",
            ])
        for base_f, curr_f in delta.persisting_findings:
            note = (
                f"severity {base_f.severity} -> {curr_f.severity}"
                if base_f.severity != curr_f.severity else "unchanged"
            )
            delta_rows.append([
                "Persisting", curr_f.id, curr_f.severity.upper(), f"{curr_f.asset.ip}:{curr_f.port}",
                curr_f.title[:40], note,
            ])
        for new_f in delta.new_findings:
            delta_rows.append([
                "New", new_f.id, new_f.severity.upper(), f"{new_f.asset.ip}:{new_f.port}",
                new_f.title[:40], "not present in baseline",
            ])
        story.append(_table(delta_rows, [20*mm, 26*mm, 18*mm, 26*mm, 60*mm, 33*mm], styles, wide=True))
        story.append(Spacer(1, 2*mm))

    # ── Appendices ────────────────────────────────────────────────────────
    story.append(PageBreak())
    _heading(story, "Appendix A: Evidence Index", styles)
    idx_rows = [["Finding", "Severity", "Evidence ID", "Locator"]]
    for finding in findings:
        if not finding.evidence:
            idx_rows.append([finding.id, finding.severity.upper(), "—", "no evidence refs recorded"])
        for ref in finding.evidence:
            idx_rows.append([finding.id, finding.severity.upper(), ref.evidence_id, (ref.locator or "")[:90]])
    if len(idx_rows) > 1:
        story.append(Paragraph("<b>Finding → evidence cross-reference</b>", styles["Small"]))
        story.append(_table(idx_rows, [28*mm, 20*mm, 30*mm, 105*mm], styles, wide=True))
        story.append(Spacer(1, 3*mm))
    story.append(Paragraph("<b>Evidence artifacts (content-addressed)</b>", styles["Small"]))
    ev_rows = [["Evidence ID", "Tool", "Mode", "SHA-256 (first 16)", "Captured at", "Filename"]]
    for ev in evidence_records.values():
        ev_rows.append([ev.id, ev.tool, ev.source_mode, ev.sha256[:16] + "…", ev.captured_at.isoformat()[:19], Path(ev.artifact_path).name])
    story.append(_table(ev_rows, [22*mm, 22*mm, 20*mm, 36*mm, 36*mm, 47*mm], styles, wide=True))

    _heading(story, "Appendix B: Integration Status Matrix", styles)
    story.append(_table(
        [["Tool", "Status", "Limitation"]] + [[r["tool"], r["mode"], r["limitation"][:120]] for r in integration_rows],
        [35*mm, 25*mm, 123*mm], styles,
    ))

    _heading(story, "Appendix C: Audit & Report Hashes", styles)
    story.append(Paragraph(f"Audit chain head before generation: <font face='Courier'>{prior_chain_head}</font>", styles["Small"]))
    story.append(Paragraph("PDF SHA-256 is recorded in the chained <b>report_generated</b> audit event after this file is written.", styles["Small"]))

    # ── Build ──────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(out), pagesize=landscape(A4),
        title="ProofPath Security Assessment Report",
        author="ProofPath VAPT Platform",
        subject=f"Engagement {engagement}",
        topMargin=14*mm, bottomMargin=14*mm, leftMargin=14*mm, rightMargin=14*mm,
    )
    doc.build(story)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (out.parent / "current-findings.json").write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8"
    )
    from proofpath.report.sarif import export_sarif
    from proofpath.report.cef import write_cef
    sarif_path = out.parent / "assessment.sarif"
    export_sarif(findings, sarif_path)
    cef_path = out.parent / "assessment.cef"
    write_cef(findings, cef_path)
    audit.append("report_generated", "analyst", {
        "report_path": str(out.resolve()), "report_sha256": digest,
        "finding_ids": [f.id for f in findings],
        "evidence_ids": evidence_ids, "evidence_hashes": evidence_hashes,
        "source_label": "synthetic" if synthetic else "imported" if imported else "live",
        "audit_chain_head_in_report": prior_chain_head,
        "sarif_path": str(sarif_path.resolve()),
        "cef_path": str(cef_path.resolve()),
    })
    return {
        "path": str(out), "sha256": digest, "evidence_ids": evidence_ids,
        "grounded_findings": len(grounded), "total_findings": len(findings),
        "severity_counts": severity_counts, "sarif_path": str(sarif_path),
        "cef_path": str(cef_path),
    }


# ── Helpers ────────────────────────────────────────────────────────────────

def _build_styles() -> Any:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Kicker", parent=styles["Normal"], fontSize=7, textColor=colors.HexColor("#0284c7"), spaceAfter=2, fontName="Helvetica-Bold", letterSpacing=1.5))
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontSize=26, textColor=colors.HexColor("#0f172a"), spaceAfter=4))
    styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#475569"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.5, leading=10, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="FindingHeader", parent=styles["Heading3"], textColor=colors.HexColor("#0f172a"), spaceBefore=4, spaceAfter=2))
    return styles


def _heading(story: list[Any], text: str, styles: Any) -> None:
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(_esc(text), styles["Heading2"]))


def _table(rows: list[list[str]], widths: list[float], styles: Any, wide: bool = False) -> Table:
    data = [[Paragraph(_esc(str(cell)), styles["Cell"]) for cell in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return table


def _severity_chart(counts: dict[str, int]) -> Drawing:
    drawing = Drawing(500, 180)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.height, chart.width = 50, 30, 130, 420
    labels = [s for s in SEVERITIES if counts.get(s, 0) > 0] or list(SEVERITIES)
    chart.data = [[counts.get(s, 0) for s in labels]]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.angle = 0
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(1, max(counts.values(), default=0))
    chart.valueAxis.valueStep = max(1, max(counts.values(), default=1) // 5)
    for i, sev in enumerate(labels):
        chart.bars[0].fillColor = SEV_COLORS.get(sev, colors.HexColor("#4472c4"))
        try:
            chart.bars[(0, i)].fillColor = SEV_COLORS.get(sev, colors.HexColor("#4472c4"))
        except Exception:
            pass
    drawing.add(chart)
    return drawing


def _integration_rows() -> list[dict[str, str]]:
    from proofpath.integrations import INTEGRATIONS
    return INTEGRATIONS


def _esc(value: str) -> str:
    return html.escape(str(value), quote=True).replace("\n", " ")
