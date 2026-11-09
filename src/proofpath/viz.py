"""Pure helpers for the attack-path and asset-risk visualizations.

These functions return plain data or themed HTML strings so they can be unit
tested without importing Streamlit.
"""

from __future__ import annotations

import html
import re

from proofpath.schemas import Finding

SEVERITIES = ("critical", "high", "medium", "low", "info", "not_provided")
_SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#94a3b8",
    "not_provided": "#475569",
}
_TECH = re.compile(r"ATT&CK:?\s*(T\d{4}(?:\.\d{3})?)\s*(?:\(([^)]*)\))?", re.IGNORECASE)


def severity_by_asset(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Asset -> severity -> count, sorted by asset address."""
    matrix: dict[str, dict[str, int]] = {}
    for finding in findings:
        row = matrix.setdefault(finding.asset.ip, {severity: 0 for severity in SEVERITIES})
        row[finding.severity] = row.get(finding.severity, 0) + 1
    return {asset: matrix[asset] for asset in sorted(matrix)}


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    value = hex_color.lstrip("#")
    red, green, blue = (int(value[index:index + 2], 16) for index in (0, 2, 4))
    return f"rgba({red},{green},{blue},{alpha:.2f})"


def heatmap_html(findings: list[Finding]) -> str:
    """Asset x severity heatmap as a themed HTML table."""
    matrix = severity_by_asset(findings)
    if not matrix:
        return ""
    severities = [s for s in SEVERITIES if any(row.get(s, 0) for row in matrix.values())] or list(SEVERITIES)
    max_count = max((row.get(s, 0) for row in matrix.values() for s in severities), default=0) or 1
    parts = ['<table style="border-collapse:collapse;font-size:0.78rem;width:100%;">']
    parts.append('<tr><th style="text-align:left;padding:6px 10px;color:#94a3b8;font-weight:600;">Asset</th>')
    for severity in severities:
        parts.append(
            f'<th style="padding:6px 10px;color:{_SEV_COLORS[severity]};font-weight:700;'
            f'text-transform:uppercase;">{html.escape(severity)}</th>'
        )
    parts.append('<th style="padding:6px 10px;color:#94a3b8;font-weight:600;">Total</th></tr>')
    for asset, row in matrix.items():
        total = sum(row.get(s, 0) for s in severities)
        parts.append(f'<tr><td style="padding:6px 10px;color:#e2e8f0;font-family:monospace;">{html.escape(asset)}</td>')
        for severity in severities:
            count = row.get(severity, 0)
            if count:
                background = _hex_to_rgba(_SEV_COLORS[severity], 0.15 + 0.6 * (count / max_count))
                parts.append(
                    f'<td style="padding:6px 10px;text-align:center;background:{background};'
                    f'color:#fff;font-weight:700;">{count}</td>'
                )
            else:
                parts.append('<td style="padding:6px 10px;text-align:center;color:#475569;">&middot;</td>')
        parts.append(f'<td style="padding:6px 10px;text-align:center;color:#e2e8f0;font-weight:700;">{total}</td></tr>')
    parts.append("</table>")
    return "".join(parts)


def attack_coverage(findings: list[Finding]) -> list[dict]:
    """Aggregate MITRE ATT&CK techniques parsed from each finding's mapped_to entries."""
    coverage: dict[str, dict] = {}
    for finding in findings:
        for mapping in finding.mapped_to:
            for technique, name in _TECH.findall(mapping):
                entry = coverage.setdefault(
                    technique,
                    {"technique": technique, "name": name.strip(), "count": 0, "assets": set(), "findings": set()},
                )
                entry["count"] += 1
                entry["assets"].add(finding.asset.ip)
                entry["findings"].add(finding.id)
    rows = [
        {
            "technique": entry["technique"],
            "name": entry["name"],
            "count": entry["count"],
            "assets": sorted(entry["assets"]),
            "findings": sorted(entry["findings"]),
        }
        for entry in coverage.values()
    ]
    rows.sort(key=lambda row: (-row["count"], row["technique"]))
    return rows


def attack_bars_html(findings: list[Finding]) -> str:
    """Horizontal bars showing how many findings map to each ATT&CK technique."""
    coverage = attack_coverage(findings)
    if not coverage:
        return ""
    max_count = max(row["count"] for row in coverage) or 1
    parts = ['<div style="font-size:0.8rem;">']
    for row in coverage:
        percent = row["count"] / max_count * 100
        label = f'{row["technique"]} {row["name"]}'.strip()
        assets = html.escape(", ".join(row["assets"]))
        parts.append(
            '<div style="margin-bottom:8px;">'
            '<div style="display:flex;justify-content:space-between;color:#cbd5e1;">'
            f'<span>{html.escape(label)}</span>'
            f'<span style="color:#94a3b8;">{row["count"]} finding(s) &middot; {assets}</span>'
            "</div>"
            '<div style="height:8px;background:rgba(255,255,255,0.06);border-radius:4px;margin-top:3px;">'
            f'<div style="height:8px;width:{percent:.1f}%;background:#a78bfa;border-radius:4px;"></div>'
            "</div></div>"
        )
    parts.append("</div>")
    return "".join(parts)


def remediation_trend_html(remediated: int, persisting: int, new: int) -> str:
    """Stacked bar summarising a retest comparison."""
    total = remediated + persisting + new
    if total == 0:
        return ""
    segments = (
        ("Remediated", remediated, "#22c55e"),
        ("Persisting", persisting, "#eab308"),
        ("New", new, "#ef4444"),
    )
    parts = ['<div style="margin:0.4rem 0 0.8rem 0;">']
    parts.append('<div style="display:flex;height:22px;border-radius:6px;overflow:hidden;">')
    for label, count, color in segments:
        if count:
            percent = count / total * 100
            parts.append(
                f'<div title="{label}: {count}" style="background:{color};width:{percent:.1f}%;'
                "display:flex;align-items:center;justify-content:center;font-size:0.68rem;"
                f'font-weight:700;color:#0b1220;">{count if percent > 8 else ""}</div>'
            )
    parts.append("</div>")
    parts.append('<div style="display:flex;gap:14px;flex-wrap:wrap;font-size:0.74rem;color:#94a3b8;margin-top:6px;">')
    for label, count, color in segments:
        parts.append(f'<span><span style="color:{color};font-weight:700;">&#9632;</span> {label}: {count}</span>')
    parts.append("</div></div>")
    return "".join(parts)
