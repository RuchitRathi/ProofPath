"""ProofPath - Enterprise Auditable Security Assessment & VAPT Console."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
OLLAMA_CONFIG_PATH = Path(os.environ.get("PROOFPATH_OLLAMA_CONFIG", ROOT / "ollama.yaml"))
SCOPE_CONFIG_PATH = Path(os.environ.get("PROOFPATH_SCOPE_CONFIG", ROOT / "scope.yaml"))
DATA_ROOT = Path(os.environ.get("PROOFPATH_DATA_DIR", ROOT / "data"))

import streamlit as st

from proofpath.adapters.base import execute_action
from proofpath.adapters.active_validate import ActiveValidationAdapter
from proofpath.adapters.burp_import import import_burp_xml
from proofpath.adapters.nessus_import import import_nessus_xml
from proofpath.adapters.openvas_import import import_openvas_xml
from proofpath.adapters.nikto_import import import_nikto_report
from proofpath.adapters.zap_import import import_zap_report
from proofpath.adapters.metasploit_import import import_metasploit_report
from proofpath.agent import AgentConfig, AgentResult, ImportRequest, StepType, VAPTAgent
from proofpath.assistant import SecurityAssistant
from proofpath.report.sarif import export_sarif
from proofpath.diff import compare_assessments
from proofpath.adapters.nmap import NmapAdapter, NmapExecutionConfig, RecordedNmapXMLAdapter
from proofpath.adapters.webscan import WebScanAdapter
from proofpath.audit import AuditLog
from proofpath.approval import decide_approval, request_approval
from proofpath.correlator import correlate_findings
from proofpath.integrations import INTEGRATIONS
from proofpath.grounding import verify_finding, verify_text
from proofpath.qa import answer_report_question
from proofpath.viz import attack_bars_html, attack_coverage, heatmap_html, remediation_trend_html
from proofpath.ledger import Ledger
from proofpath.proposer import (
    OllamaClient,
    OllamaConfig,
    PlannerCandidate,
    ProposedAction,
    ProposalGateAdapter,
    RulePlanner,
    executed_fingerprints,
    propose_and_gate,
)
from proofpath.report.generator import generate_pdf
from proofpath.risk import rank_findings
from proofpath.skeptic import analyze_findings, apply_observation_evidence, gate_recheck_proposal
from proofpath.threat_intel import load_public_threat_intel
from proofpath.xml_evidence import MAX_IMPORT_BYTES
from proofpath.schemas import Action, ActionName, Finding, ServiceObservation
from proofpath.scope_guard import ScopeGuard
from proofpath.orchestrator import sweep_cidr

# Upper bound on hosts enumerated from a single CIDR sweep in the UI.
MAX_SWEEP_HOSTS = 256

# ---------------------------------------------------------------------------
# Page config & CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ProofPath VAPT",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🔐",
)

st.markdown(
    """
    <style>
    /* ---- Layout ---- */
    .block-container { max-width: 1560px; padding-top: 1rem; padding-bottom: 2.5rem; }
    [data-testid="stHeader"] { background: transparent; }

    /* ---- Sidebar ---- */
    [data-testid="stSidebar"] > div:first-child { padding-top: 1.2rem; }

    /* ---- Metrics ---- */
    [data-testid="stMetric"] {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 10px;
        padding: 0.7rem 1rem;
    }

    /* ---- Tabs ---- */
    div[data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0; }
    button[data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 0.55rem 1rem;
        font-weight: 600;
        font-size: 0.84rem;
        color: #94a3b8;
        background: transparent;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #38bdf8;
        background: rgba(56,189,248,0.08);
        border-top: 2px solid #38bdf8;
    }

    /* ---- Buttons ---- */
    div.stButton > button { border-radius: 8px; min-height: 2.4rem; font-weight: 600; }

    /* ---- Expanders ---- */
    [data-testid="stExpander"] {
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        background: rgba(255,255,255,0.02);
    }

    /* ---- Custom components ---- */
    .pp-brand {
        display: flex; align-items: center; gap: 10px;
        padding: 0 0 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.1);
        margin-bottom: 0.75rem;
    }
    .pp-brand-icon { font-size: 1.5rem; line-height: 1; }
    .pp-brand-name { font-size: 1.05rem; font-weight: 750; color: #f1f5f9; letter-spacing: -0.02em; }
    .pp-brand-sub { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; }

    .pp-hero {
        background: linear-gradient(135deg, rgba(56,189,248,0.06) 0%, rgba(7,11,20,0) 60%);
        border: 1px solid rgba(56,189,248,0.15);
        border-radius: 12px;
        padding: 1.4rem 1.8rem 1.2rem;
        margin-bottom: 1.2rem;
    }
    .pp-hero-eyebrow { font-size: 0.72rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: #38bdf8; margin-bottom: 0.35rem; }
    .pp-hero h1 { font-size: 1.65rem; font-weight: 750; color: #f8fafc; margin: 0 0 0.4rem; letter-spacing: -0.025em; line-height: 1.2; }
    .pp-hero p { font-size: 0.88rem; color: #94a3b8; margin: 0; line-height: 1.5; max-width: 820px; }
    .pp-hero-badges { display: flex; gap: 8px; margin-top: 0.8rem; flex-wrap: wrap; }
    .pp-badge {
        display: inline-flex; align-items: center; gap: 5px;
        border: 1px solid rgba(56,189,248,0.35); color: #7dd3fc;
        background: rgba(56,189,248,0.08); border-radius: 5px;
        padding: 3px 9px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.06em;
    }
    .pp-badge.green { border-color: rgba(52,211,153,0.35); color: #6ee7b7; background: rgba(52,211,153,0.08); }
    .pp-badge.amber { border-color: rgba(251,191,36,0.35); color: #fcd34d; background: rgba(251,191,36,0.08); }
    .pp-badge.red   { border-color: rgba(239,68,68,0.35);  color: #fca5a5; background: rgba(239,68,68,0.08); }

    /* severity pills */
    .sev-crit { background: rgba(239,68,68,.18); color:#f87171; border:1px solid #ef4444; border-radius:4px; padding:2px 7px; font-size:.74rem; font-weight:700; }
    .sev-high { background: rgba(249,115,22,.18); color:#fb923c; border:1px solid #f97316; border-radius:4px; padding:2px 7px; font-size:.74rem; font-weight:700; }
    .sev-med  { background: rgba(234,179,8,.18);  color:#facc15; border:1px solid #eab308; border-radius:4px; padding:2px 7px; font-size:.74rem; font-weight:700; }
    .sev-low  { background: rgba(59,130,246,.18);  color:#60a5fa; border:1px solid #3b82f6; border-radius:4px; padding:2px 7px; font-size:.74rem; font-weight:700; }
    .sev-info { background: rgba(148,163,184,.18); color:#cbd5e1; border:1px solid #94a3b8; border-radius:4px; padding:2px 7px; font-size:.74rem; font-weight:700; }

    /* tool card */
    .tool-card {
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 0.85rem 1rem;
        background: rgba(255,255,255,0.025);
        margin-bottom: 0.6rem;
    }
    .tool-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem; }
    .tool-card-name { font-weight: 700; font-size: 0.9rem; color: #e2e8f0; }
    .tool-mode-live { color: #34d399; font-size: 0.7rem; font-weight: 700; background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.3); border-radius: 4px; padding: 2px 7px; }
    .tool-mode-import { color: #7dd3fc; font-size: 0.7rem; font-weight: 700; background: rgba(56,189,248,0.1); border: 1px solid rgba(56,189,248,0.3); border-radius: 4px; padding: 2px 7px; }
    .tool-mode-unsupported { color: #94a3b8; font-size: 0.7rem; font-weight: 700; background: rgba(148,163,184,0.1); border: 1px solid rgba(148,163,184,0.3); border-radius: 4px; padding: 2px 7px; }
    .tool-card-desc { font-size: 0.77rem; color: #64748b; }
    .tool-loaded { color: #34d399; font-size: 0.77rem; font-weight: 600; }
    .tool-empty  { color: #475569; font-size: 0.77rem; }

    /* stage stepper */
    .stepper { display: flex; gap: 4px; margin: 0.6rem 0 1.4rem; font-size: 0.72rem; }
    .step-done   { flex:1; text-align:center; padding:5px 2px; background:#0d281e; border:1px solid #059669; border-radius:6px; color:#34d399; font-weight:700; }
    .step-active { flex:1; text-align:center; padding:5px 2px; background:rgba(56,189,248,.1); border:1px solid #0284c7; border-radius:6px; color:#f8fafc; font-weight:700; }
    .step-todo   { flex:1; text-align:center; padding:5px 2px; background:rgba(255,255,255,.02); border:1px solid rgba(255,255,255,.07); border-radius:6px; color:#475569; font-weight:600; }

    /* AI inference label */
    .ai-label { display:inline-flex; align-items:center; gap:5px; font-size:0.72rem; font-weight:700;
        color:#a78bfa; background:rgba(167,139,250,0.1); border:1px solid rgba(167,139,250,0.3);
        border-radius:4px; padding:2px 8px; margin-bottom:6px; }
    .code-label { display:inline-flex; align-items:center; gap:5px; font-size:0.72rem; font-weight:700;
        color:#34d399; background:rgba(52,211,153,0.1); border:1px solid rgba(52,211,153,0.3);
        border-radius:4px; padding:2px 8px; margin-bottom:6px; }

    /* evidence ref */
    .ev-ref { display:inline-flex; align-items:center; gap:6px; font-size:0.75rem; font-weight:600;
        color:#7dd3fc; background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2);
        border-radius:5px; padding:3px 9px; margin:2px 3px; }

    /* divider */
    hr { border-color: rgba(255,255,255,0.08); }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------
GUARD = ScopeGuard.from_yaml(SCOPE_CONFIG_PATH)
AUDIT = AuditLog(DATA_ROOT / "audit.jsonl")
LEDGER = Ledger(DATA_ROOT / "evidence")
NMAP_CONFIG = NmapExecutionConfig.from_yaml(ROOT / "nmap.yaml")
NMAP_ADAPTERS = {
    ActionName.NMAP_SCAN: NmapAdapter(
        wsl_distribution=NMAP_CONFIG.distribution if NMAP_CONFIG.runtime == "wsl" else None
    )
}
WEB_ADAPTERS = {ActionName.WEB_SCAN: WebScanAdapter()}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ports(text: str) -> list[int]:
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        raise ValueError("ports are required")
    result: list[int] = []
    for part in parts:
        if not part.isdigit():
            raise ValueError("ports must be a comma-separated list of integers")
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError("ports must be between 1 and 65535")
        result.append(port)
    return result


def _append_findings(findings: list[Finding]) -> None:
    st.session_state.raw_findings.extend(findings)


def _audit_grounding_rejection(key: str, details: dict) -> None:
    seen = st.session_state.setdefault("grounding_rejections", set())
    if key not in seen:
        AUDIT.append("grounding_rejected", "grounding-verifier", details)
        seen.add(key)


def _import_failure(tool: str, filename: str, raw: bytes, error: Exception) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return (
        f"Tool: {tool} · filename: {filename} · SHA-256: {digest} · "
        f"evidence ID: none · source_mode=imported · parsed: 0 · dropped out of scope: 0 · parse errors: 1 · error: {error}"
    )


def _safe_intel():
    """Return public_threat_intel from session state only if it's the correct type."""
    from proofpath.threat_intel import PublicThreatIntel as _PTI
    val = st.session_state.get("public_threat_intel")
    return val if isinstance(val, _PTI) else None
    cls = {"critical": "sev-crit", "high": "sev-high", "medium": "sev-med", "low": "sev-low"}.get(sev, "sev-info")
    return f'<span class="{cls}">{sev.upper()}</span>'


def _show_finding_table(findings: list[Finding]) -> None:
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("critical", "high", "medium", "low")}
    info_count = len(findings) - sum(counts.values())
    st.markdown(
        f'<div style="display:flex;gap:10px;margin-bottom:12px;align-items:center;flex-wrap:wrap;">'
        f'<span class="sev-crit">Critical: {counts["critical"]}</span>'
        f'<span class="sev-high">High: {counts["high"]}</span>'
        f'<span class="sev-med">Medium: {counts["medium"]}</span>'
        f'<span class="sev-low">Low: {counts["low"]}</span>'
        f'<span class="sev-info">Info/Other: {info_count}</span>'
        f'<span style="color:#475569;font-size:0.8rem;margin-left:auto;">Total correlated: {len(findings)}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    rows = [
        {
            "Title": f.title,
            "Asset": f.asset.ip,
            "Port": str(f.port),
            "Protocol": f.protocol,
            "Severity": f.severity.upper(),
            "CVSS": str(round(f.cvss, 1)) if f.cvss is not None else "not provided",
            "Confidence": f.confidence.title(),
            "Status": f.status.replace("_", " ").title(),
            "Sources": ", ".join(f.source_tools),
            "Evidence IDs": ", ".join(dict.fromkeys(r.evidence_id for r in f.evidence)),
        }
        for f in findings
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)
    for idx, finding in enumerate(findings, 1):
        label = f"{idx}. {finding.title} — {finding.asset.ip}:{finding.port}"
        with st.expander(label):
            c1, c2 = st.columns([3, 2])
            with c1:
                st.markdown('<span class="code-label">⬡ Observed Evidence</span>', unsafe_allow_html=True)
                st.text(finding.observed)
                if finding.inference:
                    grounding = verify_finding(finding, LEDGER)
                    if grounding.accepted:
                        st.markdown('<span class="ai-label">✦ AI Inference</span>', unsafe_allow_html=True)
                        st.text(finding.inference)
                    else:
                        _audit_grounding_rejection(
                            f"finding:{finding.id}:{hash(finding.inference)}",
                            {"finding_id": finding.id,
                             "evidence_ids": [r.evidence_id for r in finding.evidence],
                             "violations": list(grounding.violations),
                             "fallback": "AI inference hidden"},
                        )
                        st.warning("AI inference hidden — grounding check failed: " + "; ".join(grounding.violations))
                if finding.conflict_notes:
                    st.warning("Cross-tool conflict: " + " | ".join(finding.conflict_notes))
            with c2:
                st.markdown('<span class="code-label">⬡ Technical Attributes</span>', unsafe_allow_html=True)
                st.text(f"CVEs   : {', '.join(finding.cves) if finding.cves else 'None reported'}")
                st.text(f"CWEs   : {', '.join(finding.cwes) if finding.cwes else 'None reported'}")
                st.text(f"CVSS   : {finding.cvss if finding.cvss is not None else 'not provided'}")
                st.text(f"Validation: {finding.validation_status}")
            st.markdown("**Cited Ledger Artifacts**")
            ev_html = " ".join(f'<span class="ev-ref">{r.evidence_id} · {r.locator}</span>' for r in finding.evidence)
            st.markdown(ev_html or "None", unsafe_allow_html=True)
            for ref in finding.evidence:
                if ref.excerpt:
                    st.code(ref.excerpt, language="xml")


# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------
_DEFAULTS = {
    "raw_findings": [],
    "observations": [],
    "transcript": [],
    "plan_proposal": None,
    "plan_status": "",
    "plan_metrics": [],
    "criticality_by_asset": {},
    "approval_records": {},
    "report_path": "",
    "cef_path": "",
    "sarif_path": "",
    "_demo_loaded": False,
    "agent_result": None,
    "agent_running": False,
    "tool_ingestion_status": {},   # tool_name -> {"count": int, "evidence_id": str}
    "ollama_warmup_status": "",
    "grounding_rejections": set(),
    "retest_baseline": None,
    "retest_label": "",
    "retest_diff": None,
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

if "public_threat_intel" not in st.session_state:
    try:
        st.session_state.public_threat_intel = load_public_threat_intel(
            DATA_ROOT / "threat_intel" / "training", LEDGER
        )
        st.session_state.public_threat_intel_error = ""
    except Exception as exc:
        st.session_state.public_threat_intel = None
        st.session_state.public_threat_intel_error = str(exc)[:300]

# ---------------------------------------------------------------------------
# Full 7-tool synthetic demo loader (explicitly user-triggered)
# ---------------------------------------------------------------------------
def _load_demo_assessment() -> None:
    """Import the synthetic 7-tool demo fixtures through the guarded import paths.

    Scope is never widened here. The demo assets (10.20.0.10) stay inside the
    authorized RFC1918 CIDRs declared in scope.yaml, so the scope guard is
    always the control that decides whether each import may run.
    """
    fixture = ROOT / "tests" / "fixtures" / "demo"
    _demo_req = Action(
        id="demo-load-nmap",
        name=ActionName.IMPORT_NMAP_XML,
        target="10.20.0.10",
        ports=[80],
        engagement_id=GUARD.policy.engagement,
        requested_by="analyst",
    )
    _res = execute_action(
        _demo_req, GUARD, AUDIT, LEDGER,
        {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter((fixture / "nmap.xml").read_bytes())},
    )
    st.session_state.observations = list(_res.services)
    _raw_f: list[Finding] = []
    st.session_state.tool_ingestion_status = {}
    _demo_tool_map = [
        ("nessus.nessus", import_nessus_xml, "Nessus"),
        ("burp.xml", import_burp_xml, "Burp Suite"),
        ("openvas.xml", import_openvas_xml, "OpenVAS"),
        ("nikto.json", import_nikto_report, "Nikto"),
        ("zap.xml", import_zap_report, "OWASP ZAP"),
        ("metasploit.xml", import_metasploit_report, "Metasploit"),
    ]
    for _fname, _fn, _tname in _demo_tool_map:
        _fpath = fixture / _fname
        if _fpath.is_file():
            _r = _fn(_fpath.read_bytes(), GUARD, AUDIT, LEDGER)
            _raw_f.extend(_r.findings)
            st.session_state.tool_ingestion_status[_tname] = {
                "count": len(_r.findings),
                "evidence_id": _r.evidence_id,
            }
    st.session_state.raw_findings = _raw_f
    st.session_state["_recon_submitted"] = False
    st.session_state["_demo_loaded"] = True


def _render_tool_coverage(slot) -> None:
    """Refresh the sidebar status cards from the latest session state."""
    with slot.container():
        st.markdown("#### Tool Coverage")
        _ingested = st.session_state.tool_ingestion_status
        _nmap_loaded = bool(st.session_state.observations)
        _sidebar_tools = [
            ("Nmap", "Live", _nmap_loaded, f"{len(st.session_state.observations)} services"),
            ("ProofPath Web Scan", "Live", "ProofPath Web Scan" in _ingested, ""),
            ("Nessus", "Import-only", "Nessus" in _ingested, f"{_ingested.get('Nessus', {}).get('count', 0)} findings"),
            ("Burp Suite", "Import-only", "Burp Suite" in _ingested, f"{_ingested.get('Burp Suite', {}).get('count', 0)} findings"),
            ("OpenVAS", "Import-only", "OpenVAS" in _ingested, f"{_ingested.get('OpenVAS', {}).get('count', 0)} findings"),
            ("Nikto", "Import-only", "Nikto" in _ingested, f"{_ingested.get('Nikto', {}).get('count', 0)} findings"),
            ("OWASP ZAP", "Import-only", "OWASP ZAP" in _ingested, f"{_ingested.get('OWASP ZAP', {}).get('count', 0)} findings"),
            ("Metasploit", "Import-only", "Metasploit" in _ingested, f"{_ingested.get('Metasploit', {}).get('count', 0)} findings"),
        ]
        for tool_name, mode, loaded, detail in _sidebar_tools:
            mode_cls = "tool-mode-live" if mode == "Live" else "tool-mode-import"
            if tool_name == "ProofPath Web Scan":
                scan = _ingested.get(tool_name)
                if scan:
                    status = scan.get("status", "unknown").upper()
                    evidence_id = scan.get("evidence_id") or "no evidence"
                    detail = f"{status} · {scan.get('count', 0)} findings · {evidence_id}"
                    status_cls = "tool-loaded" if scan.get("status") == "ok" else "tool-empty"
                    status_line = f'<span class="{status_cls}">{detail}</span>'
                else:
                    status_line = '<span class="tool-empty">Not run · explicit live scan</span>'
            else:
                status_line = (
                    f'<span class="tool-loaded">✔ {detail}</span>'
                    if loaded
                    else '<span class="tool-empty">Not loaded</span>'
                )
            st.markdown(
                f'<div class="tool-card">'
                f'  <div class="tool-card-header">'
                f'    <span class="tool-card-name">{tool_name}</span>'
                f'    <span class="{mode_cls}">{mode}</span>'
                f'  </div>'
                f'  {status_line}'
                f'</div>',
                unsafe_allow_html=True,
            )


# Determine model config
model_configured = False
model_tag_display = "Local Qwen (offline)"
try:
    _mc = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
    if _mc.model_tag.strip():
        model_configured = True
        model_tag_display = _mc.model_tag
except Exception:
    pass

# Compute merged findings once for sidebar summary
# Re-validate findings from session state to ensure schema consistency across reruns
try:
    _raw = [Finding.model_validate(f.model_dump()) if not isinstance(f, Finding) else f
            for f in st.session_state.raw_findings]
    merged_findings = correlate_findings(_raw, st.session_state.observations)
except Exception:
    merged_findings = []

# ---------------------------------------------------------------------------
# Sidebar — Mission Control
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        '<div class="pp-brand">'
        '  <div class="pp-brand-icon">🔐</div>'
        '  <div><div class="pp-brand-name">ProofPath</div>'
        '       <div class="pp-brand-sub">VAPT Platform</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Engagement scope ──────────────────────────────────────────────────
    st.markdown("#### Engagement Scope")
    scope_html = (
        f'<div style="font-size:0.8rem;color:#94a3b8;line-height:1.8;">'
        f'<b style="color:#e2e8f0;">ID</b>  {GUARD.policy.engagement}<br>'
        f'<b style="color:#e2e8f0;">CIDRs</b>  {", ".join(GUARD.policy.allowed_cidrs)}<br>'
        f'<b style="color:#e2e8f0;">Ports</b>  {", ".join(GUARD.policy.allowed_ports)}<br>'
        f'<b style="color:#e2e8f0;">Excluded</b>  {", ".join(GUARD.policy.excluded_hosts) or "None"}'
        f'</div>'
    )
    st.markdown(scope_html, unsafe_allow_html=True)
    open_scope = st.toggle(
        "Open scope (all IPs)",
        value=st.session_state.get("_open_scope_override", False),
        key="permit_all_ips_mode",
        help="Removes CIDR restriction — use only for explicitly authorized engagements.",
    )
    GUARD.policy = GUARD.policy.model_copy(update={"allow_all_ips": open_scope or st.session_state.get("_open_scope_override", False)})
    if open_scope:
        st.caption("⚠️ Universal IP scope active.")

    st.divider()

    # ── Explicit synthetic demo loader ────────────────────────────────────
    if st.button("Load Full 7-Tool Assessment", key="sidebar_load_demo", use_container_width=True):
        try:
            _load_demo_assessment()
        except Exception as exc:
            st.session_state["_demo_error"] = str(exc)
        st.rerun()
    st.caption(
        "Loads the labelled **SYNTHETIC** 7-tool dataset (host 10.20.0.10) from bundled "
        "fixtures. No network activity — safe to run during a live demo. Web Scan is a "
        "separate live operation under Scan & Recon and is not run by this button."
    )
    if st.session_state.get("_demo_error"):
        st.error(f"Error loading demo: {st.session_state.pop('_demo_error')}")

    # ── Tool status panel ─────────────────────────────────────────────────
    _tool_coverage_slot = st.empty()
    _render_tool_coverage(_tool_coverage_slot)

    st.divider()

    # ── AI engine status ──────────────────────────────────────────────────
    st.markdown("#### AI Engine")
    ai_status_color = "#34d399" if model_configured else "#f59e0b"
    ai_status_text = "Qwen 2.5 7B — Configured" if model_configured else "No model tag — rule fallback"
    st.markdown(
        f'<div style="font-size:0.82rem;color:{ai_status_color};font-weight:600;'
        f'background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);'
        f'border-radius:7px;padding:6px 10px;margin-bottom:8px;">'
        f'● {ai_status_text}</div>',
        unsafe_allow_html=True,
    )
    if st.button("Test AI Connection", key="warmup_qwen", use_container_width=True):
        try:
            m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
            OllamaClient(m_cfg).warmup()
            AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": m_cfg.model_tag, "status": "ok"})
            st.session_state.ollama_warmup_status = "✔ Connected"
        except Exception as exc:
            AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": "?", "status": "unavailable", "reason": str(exc)[:500]})
            st.session_state.ollama_warmup_status = "✗ Offline — rule planner active"
    if st.session_state.ollama_warmup_status:
        st.caption(st.session_state.ollama_warmup_status)

    st.divider()

    # ── Reset button only ─────────────────────────────────────────────────
    if st.button("Reset Assessment", key="sidebar_reset", use_container_width=True):
        st.session_state.raw_findings = []
        st.session_state.observations = []
        st.session_state.tool_ingestion_status = {}
        st.session_state.plan_proposal = None
        st.session_state.plan_status = ""
        st.session_state.approval_records = {}
        st.session_state.report_path = ""
        st.session_state.cef_path = ""
        st.session_state.sarif_path = ""
        st.session_state["_demo_loaded"] = False
        st.session_state.transcript = []
        st.session_state.agent_result = None
        st.session_state.retest_baseline = None
        st.session_state.retest_label = ""
        st.session_state.retest_diff = None
        st.session_state["_open_scope_override"] = False
        st.session_state["_recon_submitted"] = False
        st.session_state["_auto_loaded"] = False  # allow re-auto-load on next render
        st.rerun()

# ---------------------------------------------------------------------------
# Hero header
# ---------------------------------------------------------------------------
has_obs = bool(st.session_state.observations)
has_raw = bool(st.session_state.raw_findings)
has_plan = bool(st.session_state.plan_proposal)
has_approval = bool(st.session_state.approval_records)
has_report = bool(st.session_state.report_path)

if has_report:
    active_stage = 8
elif has_approval:
    active_stage = 7
elif has_raw:
    active_stage = 5
elif has_obs:
    active_stage = 4
elif has_plan:
    active_stage = 2
else:
    active_stage = 1

st.markdown(
    f"""
    <div class="pp-hero">
      <div class="pp-hero-eyebrow">Auditable Security Assessment Platform</div>
      <h1>ProofPath VAPT</h1>
      <p>Multi-tool vulnerability assessment with evidence-grounded AI reasoning, hash-chained audit integrity,
      and scope-enforced execution — every finding cites a ledger artifact you can verify.</p>
      <div class="pp-hero-badges">
        <span class="pp-badge green">● Scope Guard Active</span>
        <span class="pp-badge">⛓ Audit Chain</span>
        <span class="pp-badge">{len(merged_findings)} Findings</span>
        <span class="pp-badge">{len(st.session_state.observations)} Services</span>
        {"<span class='pp-badge green'>✦ AI Ready</span>" if model_configured else "<span class='pp-badge amber'>✦ Rule Planner</span>"}
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if st.session_state.get("_demo_loaded"):
    st.markdown(
        '<div style="border:1px solid rgba(245,158,11,0.45);background:rgba(245,158,11,0.10);'
        'border-radius:8px;padding:0.6rem 1rem;margin:0.4rem 0 0.8rem 0;color:#fcd34d;font-size:0.85rem;">'
        '⚠ <b>SYNTHETIC DEMO DATA</b> — findings below come from bundled fixture files '
        '(host 10.20.0.10), not a live engagement. Use <b>Reset Assessment</b> to clear them.'
        '</div>',
        unsafe_allow_html=True,
    )

# Stage stepper
_STAGES = [
    ("Analyst Request", 1), ("Agent Planning", 2), ("Scan", 3),
    ("Result Ingestion", 4), ("AI Analysis", 5), ("Risk Prioritization", 6),
    ("Human Review", 7), ("VAPT Report", 8),
]
stepper_html = '<div class="stepper">'
for label, n in _STAGES:
    cls = "step-done" if n < active_stage else ("step-active" if n == active_stage else "step-todo")
    mark = "✔ " if n < active_stage else ("▶ " if n == active_stage else "")
    stepper_html += f'<div class="{cls}">{mark}{label}</div>'
stepper_html += "</div>"
st.markdown(stepper_html, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# AI Intelligence Panel — auto-shown when findings exist, no button needed
# ---------------------------------------------------------------------------
if merged_findings:
    try:
        executed = executed_fingerprints(AUDIT)
        candidates, _ = RulePlanner().evaluate(
            st.session_state.observations,
            GUARD.policy.engagement,
            executed=executed,
            findings=merged_findings,
            criticality=st.session_state.criticality_by_asset,
            enabled_actions=set(GUARD.policy.enabled_actions),
            public_intel=_safe_intel(),
        )
    except Exception:
        candidates = []

    sev_counts = {s: sum(1 for f in merged_findings if f.severity == s)
                  for s in ("critical", "high", "medium", "low")}
    top_cand = candidates[0] if candidates else None

    ai_panel = (
        '<div style="border:1px solid rgba(167,139,250,0.25);border-radius:12px;'
        'background:linear-gradient(135deg,rgba(167,139,250,0.06),rgba(56,189,248,0.04));'
        'padding:1.1rem 1.4rem;margin-bottom:1.2rem;">'
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:0.75rem;">'
        '<span style="font-size:1rem;">✦</span>'
        '<span style="font-weight:750;font-size:0.92rem;color:#c4b5fd;">AI Assessment Analysis</span>'
        '<span style="font-size:0.7rem;color:#64748b;margin-left:auto;">Qwen 2.5 7B · grounded in ledger evidence</span>'
        '</div>'
    )

    # Severity summary sentence
    crit = sev_counts["critical"]; high = sev_counts["high"]
    med = sev_counts["medium"]; low = sev_counts["low"]
    if crit:
        severity_sentence = (
            f"<b style='color:#f87171;'>⚠ {crit} critical</b>"
            + (f" and <b style='color:#fb923c;'>{high} high</b>" if high else "")
            + " severity finding(s) require immediate attention. "
        )
    elif high:
        severity_sentence = f"<b style='color:#fb923c;'>⚠ {high} high</b> severity finding(s) — prioritize remediation. "
    elif med:
        severity_sentence = f"<b style='color:#facc15;'>{med} medium</b> severity finding(s) identified — review recommended. "
    else:
        severity_sentence = f"<b style='color:#60a5fa;'>{low} low/info</b> finding(s) — routine hardening. "

    # Multi-tool correlation note
    multi_tool = [f for f in merged_findings if len(f.source_tools) > 1]
    confirmed = [f for f in merged_findings if f.status == "confirmed"]
    fp_cands = [f for f in merged_findings if f.status == "false_positive_candidate"]

    correlation_line = (
        f"<b style='color:#34d399;'>{len(multi_tool)} finding(s)</b> corroborated by multiple tools — "
        f"<b>{len(confirmed)} confirmed</b>. "
        + (f"<b style='color:#fbbf24;'>{len(fp_cands)} false-positive candidate(s)</b> flagged by skeptic. " if fp_cands else "")
    )

    # Next step recommendation
    if top_cand:
        action_name = top_cand.action.name.value.upper().replace("_", " ")
        ports = ",".join(str(p) for p in top_cand.action.ports)
        next_step = (
            f"<b style='color:#7dd3fc;'>Recommended next step:</b> {action_name} on "
            f"<code style='background:rgba(255,255,255,0.08);padding:1px 6px;border-radius:3px;'>"
            f"{top_cand.action.target}:{ports}</code> — {top_cand.planner_reason}"
        )
    else:
        next_step = "<b style='color:#34d399;'>All candidates evaluated</b> — assessment is complete. Generate the PDF report."

    ai_panel += (
        f'<div style="font-size:0.87rem;color:#cbd5e1;line-height:1.7;">'
        f'{severity_sentence}<br>'
        f'{correlation_line}<br>'
        f'{next_step}'
        f'</div>'
        f'</div>'
    )
    st.markdown(ai_panel, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs — AI Assistant is Tab 1, everything flows from there
# ---------------------------------------------------------------------------
(
    tab_assistant,
    tab_scan,
    tab_ingest,
    tab_findings,
    tab_planner,
    tab_risk,
    tab_retest,
    tab_approvals,
    tab_report,
    tab_agent,
) = st.tabs([
    "✦ AI Assistant",
    "Scan & Recon",
    "Tool Ingest",
    "Findings",
    "AI Planner",
    "Risk Rank",
    "Retest",
    "Approvals",
    "Report",
    "Auto Agent",
])

# ===========================================================================
# TAB 1 — Scan & Recon
# ===========================================================================
with tab_scan:
    st.subheader("Reconnaissance — Nmap Service Discovery")
    st.caption(
        "Run a live TCP connect scan through the WSL Ubuntu Nmap adapter, "
        "or import a previously recorded Nmap XML. Enter a CIDR (e.g. 10.20.0.0/24) "
        "to sweep every in-scope host in the range — each host is still authorized "
        "individually. Every result is stored as a ledger artifact with a SHA-256 hash."
    )

    with st.form("assess"):
        c1, c2 = st.columns([3, 2])
        with c1:
            request = st.text_input(
                "Operational Objective",
                value="Network service enumeration",
                placeholder="Enumerate open services on lab host",
            )
            target = st.text_input(
                "Target IP / Hostname",
                value="",
                placeholder="e.g. 10.10.1.5, 10.20.0.10 or a CIDR like 10.20.0.0/24",
            )
        with c2:
            ports_text = st.text_input("Ports (comma-separated)", value="80,443,8080,8443")
            skip_host_discovery = st.checkbox("Disable ping (-Pn)", value=True)
            source_mode = st.radio("Execution mode", ["Live scan", "Web security scan", "Import XML"], horizontal=True)
            # Auto-detect if user is scanning a different target than what's loaded
            existing_ips = {s.ip for s in st.session_state.observations}
            replace_existing = st.checkbox(
                "Replace existing data",
                value=True,  # default ON — most users want clean results for new target
                help="Clears all current findings and observations before scanning.",
            )
        uploaded_xml = (
            st.file_uploader("Recorded Nmap XML", type=["xml"])
            if source_mode == "Import XML"
            else None
        )
        submitted = st.form_submit_button("Run Reconnaissance", type="primary", use_container_width=True)
        if submitted:
            # Capture all form values into session state at submit time
            st.session_state["_recon_target"] = target.strip()
            st.session_state["_recon_request"] = request.strip()
            st.session_state["_recon_ports"] = ports_text
            st.session_state["_recon_skip_ping"] = skip_host_discovery
            st.session_state["_recon_source_mode"] = source_mode
            st.session_state["_recon_xml"] = uploaded_xml
            st.session_state["_recon_replace"] = replace_existing
            st.session_state["_recon_submitted"] = True

    # Only execute if the button was clicked AND a target was typed
    if st.session_state.get("_recon_submitted") and st.session_state.get("_recon_target"):
        st.session_state["_recon_submitted"] = False  # consume — won't fire again on next rerun
        _target = st.session_state.pop("_recon_target", "")
        _request = st.session_state.pop("_recon_request", "")
        _ports_text = st.session_state.pop("_recon_ports", "80")
        _skip_ping = st.session_state.pop("_recon_skip_ping", True)
        _source_mode = st.session_state.pop("_recon_source_mode", "Live scan")
        _xml = st.session_state.pop("_recon_xml", None)
        _replace = st.session_state.pop("_recon_replace", False)

        # Clear existing data if scanning a new target
        if _replace:
            st.session_state.observations = []
            st.session_state.raw_findings = []
            st.session_state.tool_ingestion_status = {}
            st.session_state.plan_proposal = None
            st.session_state.plan_status = ""
            st.session_state["_auto_loaded"] = True  # prevent demo re-load after clear
            st.session_state["_demo_loaded"] = False
            st.info(f"Previous assessment cleared — scanning {_target} fresh.")
        if not _request or not _target:
            st.error("Objective and target are both required.")
        else:
            AUDIT.append("analyst_request", "analyst", {"request": _request[:500], "target": _target, "ports": _ports_text})
            try:
                ports = _ports(_ports_text)
                if _source_mode == "Import XML" and _xml is None:
                    raise ValueError("Select a recorded Nmap XML file.")
                if _source_mode == "Import XML" and len(_xml.getvalue()) > MAX_IMPORT_BYTES:
                    raise ValueError(f"Upload exceeds the {MAX_IMPORT_BYTES}-byte limit.")
                if "/" in _target:
                    if _source_mode == "Import XML":
                        raise ValueError("CIDR sweeps require Live scan mode.")
                    if _source_mode == "Web security scan":
                        raise ValueError("Web security scan probes a single host. Choose Live scan for a CIDR sweep.")
                    sweep_hosts, sweep_error = GUARD.enumerate_hosts(_target, max_hosts=MAX_SWEEP_HOSTS)
                    if sweep_error:
                        st.error("CIDR rejected by Scope Guard: " + sweep_error)
                    elif not sweep_hosts:
                        st.warning("No in-scope hosts remain inside that CIDR after exclusions.")
                    else:
                        st.info(f"CIDR orchestration — sweeping {len(sweep_hosts)} in-scope host(s) of {_target}.")
                        sweep_report = sweep_cidr(
                            GUARD, AUDIT, LEDGER, NMAP_ADAPTERS, _target, ports, sweep_hosts,
                            requester="analyst",
                        )
                        sc1, sc2, sc3 = st.columns(3)
                        sc1.metric("Hosts in scope", len(sweep_hosts))
                        sc2.metric("Scanned", sweep_report.scanned)
                        sc3.metric("Denied", sweep_report.denied)
                        st.markdown("**Per-host results**")
                        st.dataframe([row.model_dump() for row in sweep_report.results], hide_index=True, use_container_width=True)
                        if sweep_report.services:
                            st.session_state.observations.extend(sweep_report.services)
                            st.success(f"Discovered {len(sweep_report.services)} service(s) across the range.")
                        else:
                            st.info("No active ports found across the swept range.")
                else:
                    if _source_mode == "Web security scan":
                        action = Action(
                            id=uuid.uuid4().hex,
                            name=ActionName.WEB_SCAN,
                            target=_target,
                            ports=ports,
                            arguments={},
                            engagement_id=GUARD.policy.engagement,
                            requested_by="analyst",
                        )
                        adapters = WEB_ADAPTERS
                    else:
                        action = Action(
                            id=uuid.uuid4().hex,
                            name=ActionName.NMAP_SCAN,
                            target=_target,
                            ports=ports,
                            arguments={
                                "service_detection": True,
                                "skip_host_discovery": _skip_ping,
                                "timing": 2,
                                "host_timeout_seconds": 60,
                            },
                            engagement_id=GUARD.policy.engagement,
                            requested_by="analyst",
                        )
                        if _source_mode == "Import XML":
                            action.name = ActionName.IMPORT_NMAP_XML
                            adapters = {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(_xml.getvalue())}
                        else:
                            adapters = NMAP_ADAPTERS
                    result = execute_action(action, GUARD, AUDIT, LEDGER, adapters)
                    source_label = "imported" if _source_mode == "Import XML" else "live"

                    rc1, rc2, rc3 = st.columns(3)
                    rc1.metric("Scope", "Authorized" if result.decision.allowed else "Denied")
                    rc2.metric("Status", result.status.upper())
                    rc3.metric("Evidence ID", result.evidence_id or "—")

                    # Verbose lines for audit trail (also consumed by AppTests)
                    st.write(f"Scope allowed: **{result.decision.allowed}**")
                    st.write(f"Reason: {result.decision.reason}")
                    st.write(f"Status: `{result.status}` · source mode: **{source_label}**")
                    st.write(f"Evidence ID: `{result.evidence_id or 'none'}`")

                    if result.decision.allowed:
                        st.success(result.decision.reason)
                    else:
                        st.error("Denied by Scope Guard: " + result.decision.reason)

                    if _source_mode == "Web security scan":
                        st.session_state.tool_ingestion_status["ProofPath Web Scan"] = {
                            "count": len(result.findings),
                            "evidence_id": result.evidence_id or "",
                            "status": result.status,
                        }

                    if result.findings:
                        _append_findings(result.findings)
                        st.markdown(f"**Web security findings — {len(result.findings)}**")
                        _show_finding_table(result.findings)

                    if _source_mode == "Web security scan":
                        _render_tool_coverage(_tool_coverage_slot)
                        if result.status != "ok":
                            st.warning(
                                f"Web Scan did not complete successfully (status: {result.status}). "
                                f"No clean result can be concluded. Review evidence "
                                f"{result.evidence_id or 'not recorded'} for endpoint errors."
                            )
                        elif not result.findings:
                            st.info("No web security issues detected on the probed endpoint(s).")
                    elif result.services:
                        st.session_state.observations.extend(result.services)
                        st.markdown("**Discovered Services**")
                        st.dataframe([s.model_dump() for s in result.services], hide_index=True, use_container_width=True)
                    else:
                        st.info("No active ports found in the specified range.")
            except ValueError as exc:
                st.error(str(exc))

    if st.session_state.observations:
        st.markdown("---")
        st.markdown(f"**Current service inventory — {len(st.session_state.observations)} services**")
        st.dataframe(
            [s.model_dump() for s in st.session_state.observations],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.markdown(
            '<div style="border:1px dashed rgba(255,255,255,0.1);border-radius:10px;padding:1.5rem;'
            'text-align:center;color:#475569;margin-top:1rem;">'
            '<div style="font-size:1.5rem;margin-bottom:0.5rem;">📡</div>'
            '<div style="font-weight:600;margin-bottom:0.25rem;">No services discovered yet</div>'
            '<div style="font-size:0.83rem;">Run a scan above, or use <b>Load demo assessment</b> in the sidebar.</div>'
            '</div>',
            unsafe_allow_html=True,
        )


# ===========================================================================
# TAB 2 — Tool Ingest
# ===========================================================================
with tab_ingest:
    st.subheader("Security Tool Report Ingestion")
    st.caption(
        "Upload reports from your security tools. Each file is SHA-256 hashed and stored "
        "as a ledger artifact. Findings are scope-filtered before ingestion."
    )

    # helper: render a tool ingestion section
    def _ingest_section(
        tool_display: str,
        tool_key: str,
        file_types: list[str],
        file_key: str,
        btn_key: str,
        fn,
        mode_note: str,
    ) -> None:
        loaded = tool_display in st.session_state.tool_ingestion_status
        loaded_info = st.session_state.tool_ingestion_status.get(tool_display, {})
        mode_cls = "tool-mode-import"
        status_line = (
            f'<span class="tool-loaded">✔ {loaded_info.get("count", 0)} findings ingested'
            f' · Evidence {loaded_info.get("evidence_id", "")}</span>'
            if loaded
            else '<span class="tool-empty">Not loaded</span>'
        )
        st.markdown(
            f'<div class="tool-card">'
            f'  <div class="tool-card-header">'
            f'    <span class="tool-card-name">{tool_display}</span>'
            f'    <span class="{mode_cls}">Import-only</span>'
            f'  </div>'
            f'  <div class="tool-card-desc">{mode_note}</div>'
            f'  <div style="margin-top:4px;">{status_line}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader(f"Upload {tool_display} report", type=file_types, key=file_key)
        if st.button(f"Ingest {tool_display}", key=btn_key, use_container_width=True):
            if uploaded is None:
                st.error(f"Select a {tool_display} report file first.")
            else:
                raw = uploaded.getvalue()
                try:
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit.")
                    res = fn(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.session_state.tool_ingestion_status[tool_display] = {
                        "count": len(res.findings),
                        "evidence_id": res.evidence_id,
                    }
                    st.success(
                        f"Ingested {res.parsed_items} items · {res.dropped_items if hasattr(res, 'dropped_items') else '?'} dropped "
                        f"(out of scope) · Evidence: {res.evidence_id}"
                    )
                    st.rerun()
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": tool_display, "filename": uploaded.name, "error": str(exc)[:500]})
                    st.error(_import_failure(tool_display, uploaded.name, raw, exc))

    col_l, col_r = st.columns(2)
    with col_l:
        _ingest_section(
            "Nessus", "nessus", ["nessus", "xml"], "nessus_import_file", "import_nessus",
            import_nessus_xml,
            "Imports NessusClientData_v2 XML — CVEs, CVSS scores, plugin findings.",
        )
        st.markdown("<br>", unsafe_allow_html=True)
        _ingest_section(
            "OpenVAS", "openvas", ["xml"], "openvas_import_file", "import_openvas",
            import_openvas_xml,
            "Imports OpenVAS / Greenbone XML reports — vulnerability checks, CVSS, CVE refs.",
        )
        st.markdown("<br>", unsafe_allow_html=True)
        _ingest_section(
            "OWASP ZAP", "zap", ["xml", "json"], "zap_import_file", "import_zap",
            import_zap_report,
            "Imports OWASP ZAP alert reports — web app risks, CWE/WASC classifications.",
        )
    with col_r:
        _ingest_section(
            "Burp Suite", "burp", ["xml"], "burp_import_file", "import_burp",
            import_burp_xml,
            "Imports Burp Suite issue XML — request/response evidence, severity, confidence.",
        )
        st.markdown("<br>", unsafe_allow_html=True)
        _ingest_section(
            "Nikto", "nikto", ["json", "xml"], "nikto_import_file", "import_nikto",
            import_nikto_report,
            "Imports Nikto JSON/XML — web server misconfigs, sensitive paths, header issues.",
        )
        st.markdown("<br>", unsafe_allow_html=True)
        _ingest_section(
            "Metasploit", "metasploit", ["xml", "json"], "metasploit_import_file", "import_metasploit",
            import_metasploit_report,
            "Imports lab-controlled Metasploit verification exports. Autonomous exploitation is prohibited.",
        )

    if not st.session_state.tool_ingestion_status:
        st.info(
            "No tools loaded yet. Upload reports above, or click **Load demo assessment** "
            "in the sidebar to populate all 7 tools with synthetic fixtures."
        )


# ===========================================================================
# TAB 3 — Findings
# ===========================================================================
with tab_findings:
    # Re-run skeptic updates
    updated: list[Finding] = []
    for rf in st.session_state.raw_findings:
        u = apply_observation_evidence(rf, st.session_state.observations)
        if u.status != rf.status:
            AUDIT.append("skeptic_status_updated", "skeptic", {
                "finding_id": u.id, "old_status": rf.status, "new_status": u.status,
                "evidence": [r.model_dump(mode="json") for r in u.evidence if r not in rf.evidence],
            })
        updated.append(u)
    st.session_state.raw_findings = updated
    merged_findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)

    st.subheader("Correlated Vulnerability Findings")
    if merged_findings:
        _show_finding_table(merged_findings)

        st.markdown("---")
        st.markdown("#### Skeptic Validation Hypotheses")
        st.caption("Rule-based skeptic generates evidence-linked hypotheses and proposes one-port rechecks.")
        hypotheses = analyze_findings(merged_findings, st.session_state.observations, GUARD.policy.engagement)
        if hypotheses:
            for item in hypotheses:
                with st.expander(f"[{item.hypothesis.id}] {item.hypothesis.statement}"):
                    ev_for = ", ".join(r.evidence_id for r in item.hypothesis.evidence_for) or "None"
                    ev_against = ", ".join(r.evidence_id for r in item.hypothesis.evidence_against) or "None"
                    col_h1, col_h2 = st.columns(2)
                    col_h1.markdown(f'<span class="ev-ref">For: {ev_for}</span>', unsafe_allow_html=True)
                    col_h2.markdown(f'<span class="ev-ref">Against: {ev_against}</span>', unsafe_allow_html=True)
                    st.caption("Reasoning: " + item.planner_reason)
                    if st.button("Propose recheck", key="skeptic_" + item.hypothesis.id):
                        try:
                            r = gate_recheck_proposal(item, GUARD, AUDIT, LEDGER)
                            st.info(r.status + " · " + r.message)
                        except Exception as exc:
                            st.error(str(exc))
        else:
            st.caption("No hypotheses generated yet.")
    else:
        st.markdown(
            '<div style="border:1px dashed rgba(255,255,255,0.1);border-radius:10px;padding:2rem;'
            'text-align:center;color:#475569;">'
            '<div style="font-size:1.5rem;margin-bottom:0.5rem;">🔍</div>'
            '<div style="font-weight:600;margin-bottom:0.25rem;">No findings yet</div>'
            '<div style="font-size:0.83rem;">Ingest tool reports in <b>Tool Ingest</b>, '
            'or click <b>Load demo assessment</b> in the sidebar.</div>'
            '</div>',
            unsafe_allow_html=True,
        )


# ===========================================================================
# TAB 4 — AI Planner
# ===========================================================================
with tab_planner:
    st.subheader("AI-Driven Adaptive Assessment Planner")
    st.caption(
        "The rule engine evaluates current findings and observations against all 7 tools "
        "to generate typed next-step candidates. The local Qwen model selects the highest-priority "
        "candidate and provides a grounded rationale — or the deterministic top candidate is used "
        "if the model is offline."
    )

    executed = executed_fingerprints(AUDIT)
    candidates, skipped_candidates = RulePlanner().evaluate(
        st.session_state.observations,
        GUARD.policy.engagement,
        executed=executed,
        findings=merged_findings,
        criticality=st.session_state.criticality_by_asset,
        enabled_actions=set(GUARD.policy.enabled_actions),
        public_intel=_safe_intel(),
    )

    if not candidates:
        st.info(
            "All assessment candidates for current observations have been evaluated. "
            "Add more tool reports or run a new scan to generate new candidates."
        )
    else:
        # Candidate summary cards
        st.markdown(f"**{len(candidates)} candidate next steps** — evaluated across all 7 security tools")
        for cand in candidates[:8]:
            port_str = ",".join(str(p) for p in cand.action.ports)
            tool_name = cand.action.name.value.upper().replace("_", " ")
            ev_ids = ", ".join(cand.observed_evidence_ids) or "None"
            score_str = str(round(cand.risk_score, 1)) if cand.risk_score is not None else "—"
            with st.expander(f"{cand.candidate_id}  ·  {tool_name}  ·  {cand.action.target}:{port_str}  ·  Score {score_str}"):
                cc1, cc2 = st.columns(2)
                cc1.markdown('<span class="code-label">⬡ Rule reason</span>', unsafe_allow_html=True)
                cc1.write(cand.planner_reason)
                cc1.caption(f"Exposure: {cand.exposure_state}  ·  Evidence: {ev_ids}")
                cc2.markdown('<span class="code-label">⬡ Expected result</span>', unsafe_allow_html=True)
                cc2.write(cand.expected_result)

        st.divider()

        # Generate plan button
        ai_btn_label = (
            "Generate plan with Qwen AI"
            if model_configured
            else "Generate plan"
        )
        if not model_configured:
            st.info(
                "Qwen model is not configured. The planner will use the deterministic rule-ranked candidate. "
                "To enable AI reasoning, set the model tag in `ollama.yaml`."
            )

        if st.button(ai_btn_label, key="generate_plan", type="primary"):
            with st.spinner("Consulting AI planner…"):
                try:
                    configured = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                    client = OllamaClient(configured)
                    metrics_start = len(client.metrics_history)
                    proposal, result, used_fallback = propose_and_gate(
                        st.session_state.observations, candidates, client,
                        GUARD, AUDIT, LEDGER, findings=merged_findings,
                    )
                    st.session_state.plan_proposal = proposal
                    st.session_state.plan_candidate_context = next(
                        (c for c in candidates if proposal and c.candidate_id == proposal.candidate_id), None
                    )
                    st.session_state.plan_status = result.status if result else ""
                    st.session_state.plan_fallback = used_fallback
                    st.session_state.plan_metrics = client.metrics_history[metrics_start:]
                    st.session_state.plan_run_result = None
                except Exception as exc:
                    AUDIT.append("proposer_unavailable", "model-proposer", {"reason": str(exc)[:500]})
                    proposal, result, used_fallback = propose_and_gate(
                        st.session_state.observations, candidates, None,
                        GUARD, AUDIT, LEDGER, findings=merged_findings,
                    )
                    st.session_state.plan_proposal = proposal
                    st.session_state.plan_candidate_context = next(
                        (c for c in candidates if proposal and c.candidate_id == proposal.candidate_id), None
                    )
                    st.session_state.plan_status = result.status if result else ""
                    st.session_state.plan_fallback = used_fallback
                    st.session_state.plan_metrics = []
                    st.session_state.plan_run_result = None
                    st.warning("Proposer unavailable: deterministic top rule-ranked candidate shown")

    # Show proposal result
    proposal = st.session_state.plan_proposal
    if proposal is not None:
        selected_cand = st.session_state.get("plan_candidate_context") or next(
            (c for c in (candidates if candidates else []) if c.action == proposal.action), None
        )
        used_fallback = st.session_state.get("plan_fallback", False)
        plan_metrics = st.session_state.get("plan_metrics", [])

        st.divider()
        st.markdown("### Selected Next Operation")

        # AI vs deterministic label
        if used_fallback:
            st.markdown('<span class="code-label">⬡ Deterministic rule selection</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="ai-label">✦ AI-selected (Qwen 2.5 7B)</span>', unsafe_allow_html=True)

        # Action summary
        action_str = proposal.action.name.value.upper().replace("_", " ")
        port_str = ",".join(str(p) for p in proposal.action.ports)
        st.markdown(
            f'<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.09);'
            f'border-radius:8px;padding:0.75rem 1rem;margin:0.5rem 0 1rem;">'
            f'<span style="color:#f1f5f9;font-weight:700;">{action_str}</span>'
            f' &nbsp;·&nbsp; <span style="color:#94a3b8;">{proposal.action.target}:{port_str}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        p1, p2 = st.columns(2)
        with p1:
            st.markdown('<span class="code-label">⬡ Decision trace (code generated)</span>', unsafe_allow_html=True)
            if selected_cand is not None:
                st.write(selected_cand.planner_reason)
                st.write(f"Expected result: {selected_cand.expected_result}")
            if proposal.action.name == ActionName.NMAP_SCAN:
                st.caption("This is a one-port Nmap TCP connect recheck — not a full scan.")
            st.caption(f"Status: {st.session_state.plan_status.upper()}")
        with p2:
            st.markdown("**Observed facts (code generated)**")
            st.markdown('<span class="ai-label">✦ AI rationale (model output)</span>', unsafe_allow_html=True)
            st.write("**Observed:** " + " ".join(proposal.rationale.observed))
            st.write("**Inference:** " + proposal.rationale.inferred)
            st.write("**Justification:** " + proposal.rationale.why)

        if plan_metrics:
            m = plan_metrics[-1]
            dur = m.get('total_duration_s')
            dur_str = f"{dur:.2f}s" if isinstance(dur, (int, float)) else "?s"
            st.caption(
                f"Model call: {dur_str} total · "
                f"{m.get('prompt_tokens', '?')} prompt tokens · "
                f"{m.get('output_tokens', '?')} output tokens"
            )

        # Authorization controls
        if st.session_state.plan_status == "planned":
            ba1, ba2 = st.columns(2)
            if ba1.button("Authorize Operation", key="approve_plan", type="primary"):
                checked = execute_action(
                    proposal.action, GUARD, AUDIT, LEDGER,
                    {proposal.action.name: ProposalGateAdapter(candidate_match=True, proposal=proposal)},
                )
                if checked.decision.allowed:
                    AUDIT.append("plan_approved", "analyst", {"action_id": proposal.action.id})
                    st.session_state.plan_status = "approved"
                    st.success("Operation authorized.")
                else:
                    st.error("Scope authorization failed: " + checked.message)
            if ba2.button("Skip Action", key="skip_plan"):
                AUDIT.append("plan_skipped", "analyst", {"action_id": proposal.action.id})
                st.session_state.plan_status = "skipped"
                st.info("Action skipped.")

        if st.session_state.plan_status == "approved" and proposal.action.name == ActionName.NMAP_SCAN:
            if st.button("Execute Verification Probe", key="run_plan_nmap", type="primary"):
                analyst_action = proposal.action.model_copy(update={"requested_by": "analyst"})
                run_res = execute_action(analyst_action, GUARD, AUDIT, LEDGER, NMAP_ADAPTERS)
                if run_res.services:
                    st.session_state.observations.extend(run_res.services)
                st.success(f"Probe complete: status={run_res.status} · evidence={run_res.evidence_id}")


# ===========================================================================
# TAB 5 — Risk Rank
# ===========================================================================
with tab_risk:
    st.subheader("Multi-Factor Risk Prioritization")
    public_intel = _safe_intel()
    if public_intel:
        st.caption(
            f"Threat feeds active — CISA KEV ({public_intel.kev_evidence_id}) · "
            f"FIRST EPSS ({public_intel.epss_evidence_id})"
        )
    elif st.session_state.public_threat_intel_error:
        st.caption(f"Threat feeds unavailable: {st.session_state.public_threat_intel_error}")

    findings_for_risk = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    if findings_for_risk:
        assets = sorted({f.asset.ip for f in findings_for_risk})
        st.markdown("**Asset Criticality**")
        crit_cols = st.columns(min(len(assets), 4))
        for i, asset in enumerate(assets):
            prev = st.session_state.criticality_by_asset.get(asset, "medium")
            sel = crit_cols[i % len(crit_cols)].selectbox(
                f"Asset criticality ({asset})", ["low", "medium", "high"],
                index=["low", "medium", "high"].index(prev),
                key=f"crit_{asset}",
            )
            if sel != prev:
                st.session_state.criticality_by_asset[asset] = sel
                AUDIT.append("asset_criticality_changed", "analyst", {"asset": asset, "old": prev, "new": sel})

        ranked = rank_findings(
            findings_for_risk, st.session_state.observations,
            st.session_state.criticality_by_asset, public_intel,
        )
        if ranked:
            # Severity distribution mini-chart
            sev_counts = {s: sum(1 for f in findings_for_risk if f.severity == s)
                          for s in ("critical", "high", "medium", "low", "info", "not_provided")}
            sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                          "low": "#3b82f6", "info": "#94a3b8", "not_provided": "#475569"}
            total = sum(sev_counts.values()) or 1
            bar_html = '<div style="display:flex;gap:2px;height:20px;border-radius:6px;overflow:hidden;margin-bottom:0.5rem;">'
            for sev, count in sev_counts.items():
                if count:
                    pct = count / total * 100
                    bar_html += (
                        f'<div title="{sev}: {count}" style="background:{sev_colors[sev]};'
                        f'width:{pct:.1f}%;display:flex;align-items:center;justify-content:center;'
                        f'font-size:0.65rem;font-weight:700;color:#fff;">'
                        + (f"{count}" if pct > 6 else "") + "</div>"
                    )
            bar_html += "</div>"
            bar_html += '<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:0.75rem;color:#94a3b8;margin-bottom:0.75rem;">'
            for sev, count in sev_counts.items():
                if count:
                    bar_html += f'<span><span style="color:{sev_colors[sev]};font-weight:700;">■</span> {sev}: {count}</span>'
            bar_html += "</div>"
            st.markdown(bar_html, unsafe_allow_html=True)
            rows = []
            for item in ranked:
                factor_text = "; ".join(
                    f"{f.name}={f.value} ({f.source})"
                    for f in item.factors if f.included
                )
                rows.append({
                    "Rank": item.rank,
                    "ID": item.finding.id,
                    "Asset": item.finding.asset.ip,
                    "Severity": item.finding.severity.upper(),
                    "CVSS": str(round(item.finding.cvss, 1)) if item.finding.cvss is not None else "not provided",
                    "Status": item.status_label,
                    "Score": str(round(item.priority_score, 1)) if item.priority_score is not None else "N/A",
                    "Risk Factors": factor_text,
                })
            st.caption(f"Risk table rendered · {len(ranked)} ranked finding(s)")
            st.dataframe(rows, hide_index=True, use_container_width=True)

            st.markdown("#### Attack Surface Heatmap")
            st.caption("Findings per asset by severity — darker cells hold more findings.")
            _heatmap = heatmap_html(findings_for_risk)
            if _heatmap:
                st.markdown(_heatmap, unsafe_allow_html=True)

            st.markdown("#### MITRE ATT&CK Technique Coverage")
            _coverage = attack_coverage(findings_for_risk)
            if _coverage:
                st.markdown(attack_bars_html(findings_for_risk), unsafe_allow_html=True)
            else:
                st.caption("No ATT&CK technique mappings are present in the current findings.")
    else:
        st.markdown(
            '<div style="border:1px dashed rgba(255,255,255,0.1);border-radius:10px;padding:2rem;'
            'text-align:center;color:#475569;">'
            '<div style="font-size:1.5rem;margin-bottom:0.5rem;">📊</div>'
            '<div style="font-weight:600;margin-bottom:0.25rem;">No findings to rank yet</div>'
            '<div style="font-size:0.83rem;">Ingest tool reports first.</div>'
            '</div>',
            unsafe_allow_html=True,
        )


# ===========================================================================
# TAB 6 — Retest / Remediation Verification
# ===========================================================================
with tab_retest:
    st.subheader("Retest & Remediation Verification")
    st.caption(
        "Snapshot the current correlated findings as a baseline, then re-run your scans and compare. "
        "The comparison is deterministic: it matches findings on the correlation key, not on free text."
    )

    _retest_current = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    _retest_baseline = st.session_state.retest_baseline

    rc1, rc2 = st.columns(2)
    rc1.metric("Current findings", len(_retest_current))
    rc2.metric("Baseline findings", len(_retest_baseline) if _retest_baseline is not None else "—")

    if st.button("Snapshot current findings as baseline", disabled=not _retest_current, use_container_width=True):
        st.session_state.retest_baseline = [f.model_copy(deep=True) for f in _retest_current]
        st.session_state.retest_label = datetime.now(timezone.utc).isoformat()[:19].replace("T", " ") + " UTC"
        st.session_state.retest_diff = None
        AUDIT.append("retest_baseline", "analyst", {
            "count": len(_retest_current), "finding_ids": [f.id for f in _retest_current],
        })
        st.success(f"Baseline recorded — {len(_retest_current)} finding(s).")
        st.rerun()

    if _retest_baseline is not None:
        st.caption(f"Baseline captured {st.session_state.retest_label}.")
        if st.button("Compare current findings to baseline", use_container_width=True, type="primary"):
            diff = compare_assessments(_retest_baseline, _retest_current)
            st.session_state.retest_diff = diff
            AUDIT.append("retest_compared", "analyst", {
                "baseline": len(_retest_baseline), "current": len(_retest_current),
                **diff.summary(),
            })

    _retest_diff = st.session_state.retest_diff
    if _retest_diff is not None:
        dc1, dc2, dc3 = st.columns(3)
        dc1.metric("Remediated", _retest_diff.total_remediated)
        dc2.metric("Persisting", _retest_diff.total_persisting)
        dc3.metric("New", _retest_diff.total_new)
        _trend = remediation_trend_html(
            _retest_diff.total_remediated, _retest_diff.total_persisting, _retest_diff.total_new
        )
        if _trend:
            st.markdown(_trend, unsafe_allow_html=True)

        rows = (
            [{"change": "Remediated", "id": f.id, "severity": f.severity, "asset": f"{f.asset.ip}:{f.port}", "title": f.title}
             for f in _retest_diff.remediated_findings]
            + [{"change": "Persisting", "id": curr.id, "severity": curr.severity, "asset": f"{curr.asset.ip}:{curr.port}", "title": curr.title}
               for _, curr in _retest_diff.persisting_findings]
            + [{"change": "New", "id": f.id, "severity": f.severity, "asset": f"{f.asset.ip}:{f.port}", "title": f.title}
               for f in _retest_diff.new_findings]
        )
        if rows:
            st.markdown("**Change detail**")
            st.dataframe(rows, hide_index=True, use_container_width=True)
        else:
            st.info("No findings changed between the baseline and the current state.")
        st.caption("The Report tab includes this comparison as section 7.8 when a baseline exists.")
    elif _retest_baseline is None:
        st.info("No baseline yet. Run your scans, then snapshot the findings to enable comparison.")


# ===========================================================================
# TAB 7 — Approvals
# ===========================================================================
with tab_approvals:
    st.subheader("Human Authorization — Active Validation")
    st.caption(
        "Active HTTP validation (GET/HEAD) requires dual-key human approval before execution. "
        "This enforces Hard Rule #6 — no autonomous active exploitation."
    )

    findings_for_approval = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    web_findings = [
        f for f in findings_for_approval
        if f.port in {80, 443, 8080, 8443} or (f.service or "").casefold() in {"http", "https"}
    ]

    if web_findings:
        selected_finding = st.selectbox(
            "Select Finding",
            web_findings,
            format_func=lambda f: f"{f.id} · {f.asset.ip}:{f.port} · {f.title}",
            key="approval_finding",
        )
        with st.form("approval_request_form"):
            ar1, ar2, ar3 = st.columns(3)
            requester = ar1.text_input("Requester identity", value="analyst")
            method = ar2.selectbox("HTTP Method", ["GET", "HEAD"])
            path_options = GUARD.policy.allowed_validation_paths or ["/"]
            path = ar3.selectbox("Allowlisted Path", path_options)
            justification = st.text_input("Reason for this non-destructive check", value="Confirm the local test service")
            req_sub = st.form_submit_button("Request approval", type="primary")

        if req_sub:
            try:
                action = Action(
                    id=uuid.uuid4().hex,
                    name=ActionName.ACTIVE_VALIDATE,
                    target=selected_finding.asset.ip,
                    ports=[selected_finding.port],
                    arguments={"method": method, "path": path, "finding_id": selected_finding.id},
                    engagement_id=GUARD.policy.engagement,
                    requested_by=requester.strip(),
                )
                scope_result = execute_action(action, GUARD, AUDIT, LEDGER, {})
                if "approval" in scope_result.message:
                    approval = request_approval(action, requester.strip(), justification)
                    st.session_state.approval_records[approval.id] = {"request": approval, "action": action}
                    AUDIT.append("approval_requested", requester.strip(), {
                        "approval_id": approval.id, "action_id": action.id,
                        "action_hash": approval.action_hash, "requested_by": approval.requested_by,
                        "action": action.model_dump(mode="json"), "justification": approval.justification,
                        "expires_at": approval.expires_at.isoformat(),
                    })
                    st.success("Approval request staged — awaiting a distinct authorized approver.")
                else:
                    st.error("Scope Guard denied the request: " + scope_result.message)
            except Exception as exc:
                st.error("Authorization error: " + str(exc))
    else:
        st.info("No web findings available. Ingest Burp, Nikto, or ZAP reports to surface web vulnerabilities.")

    if st.session_state.approval_records:
        st.divider()
        approver = st.text_input("Approver identity", value="engagement-director", key="approval_approver")
        for approval_id, record in list(st.session_state.approval_records.items()):
            approval = record["request"]
            action = record["action"]
            state_color = {"pending": "#f59e0b", "approved": "#34d399", "denied": "#f87171"}.get(
                approval.state.value, "#94a3b8"
            )
            st.markdown(
                f'<div style="border:1px solid rgba(255,255,255,0.08);border-radius:8px;'
                f'padding:0.7rem 1rem;margin-bottom:0.5rem;">'
                f'<span style="font-weight:700;color:#e2e8f0;">[{approval.id[:8]}]</span>&nbsp;&nbsp;'
                f'<code>{action.arguments["method"]} {action.target}:{action.ports[0]}{action.arguments["path"]}</code>'
                f'&nbsp;&nbsp;Requested by: <code>{approval.requested_by}</code>'
                f'&nbsp;&nbsp;<span style="color:{state_color};font-weight:700;">{approval.state.value.upper()}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
            if approval.state.value == "pending":
                bc1, bc2 = st.columns(2)
                if bc1.button("Approve", key=f"app_{approval_id}", type="primary"):
                    try:
                        decided = decide_approval(approval, approver, approved=True)
                        record["request"] = decided
                        AUDIT.append("approval_decision", approver, {
                            "approval_id": approval.id, "state": decided.state.value,
                        })
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
                if bc2.button("Deny", key=f"deny_{approval_id}"):
                    try:
                        decided = decide_approval(approval, approver, approved=False)
                        record["request"] = decided
                        AUDIT.append("approval_decision", approver, {
                            "approval_id": approval.id, "state": decided.state.value,
                        })
                        if decided.state.value == "denied":
                            st.session_state.raw_findings = [
                                f.model_copy(update={"validation_status": "rejected_by_human"})
                                if f.id == action.arguments["finding_id"] else f
                                for f in st.session_state.raw_findings
                            ]
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
            elif approval.state.value == "approved" and approval.used_at is None:
                if st.button("Run approved request once", key=f"run_{approval_id}", type="primary"):
                    try:
                        run_result = execute_action(
                            action, GUARD, AUDIT, LEDGER,
                            {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(action, approval)},
                            approval=approval,
                        )
                        record["request"] = approval.model_copy(update={"used_at": datetime.now(timezone.utc)})
                        outcome = next(
                            (e for e in reversed(AUDIT.read_entries())
                             if e.event_type == "active_validation_outcome"
                             and e.details.get("approval_id") == approval_id),
                            None,
                        )
                        if outcome and outcome.details.get("validation_status") == "validated_approved":
                            st.session_state.raw_findings = [
                                f.model_copy(update={"validation_status": "validated_approved"})
                                if f.id == action.arguments["finding_id"] else f
                                for f in st.session_state.raw_findings
                            ]
                        st.success(f"Done: {run_result.message}")
                        st.rerun()
                    except Exception as exc:
                        st.error("Execution failed safely: " + str(exc))


# ===========================================================================
# TAB 8 — Report
# ===========================================================================
with tab_report:
    st.subheader("Executive & Technical Assessment Report")
    findings_for_report = correlate_findings(st.session_state.raw_findings, st.session_state.observations)

    if not findings_for_report:
        st.info("Ingest at least one tool report to generate a PDF.")
    else:
        rc1, rc2 = st.columns(2)
        with rc1:
            st.markdown(f"**{len(findings_for_report)} findings** ready for report generation.")
            if st.button("Generate PDF report", disabled=not findings_for_report, type="primary", use_container_width=True):
                try:
                    report_dir = DATA_ROOT / "reports"
                    report_dir.mkdir(parents=True, exist_ok=True)
                    report_result = generate_pdf(
                        findings_for_report, st.session_state.observations, LEDGER, AUDIT,
                        report_dir / "assessment.pdf",
                        engagement=GUARD.policy.engagement,
                        scope_cidrs=GUARD.policy.allowed_cidrs,
                        criticality=st.session_state.criticality_by_asset,
                        public_intel=_safe_intel(),
                        baseline_findings=st.session_state.get("retest_baseline"),
                    )
                    st.session_state.report_path = report_result["path"]
                    st.session_state.report_hash = report_result["sha256"]
                    st.session_state.sarif_path = report_result.get("sarif_path", "")
                    st.session_state.cef_path = report_result.get("cef_path", "")
                    st.session_state.report_status = (
                        f"Grounded: {report_result['grounded_findings']}/{report_result['total_findings']}"
                    )
                    st.success("Report generated and cryptographically hashed.")
                except Exception as exc:
                    AUDIT.append("report_generation_failed", "analyst", {"reason": f"{type(exc).__name__}: {exc}"[:500]})
                    st.error("Report generation error: " + str(exc))

        if st.session_state.report_path and Path(st.session_state.report_path).is_file():
            with rc2:
                st.markdown(f"**SHA-256**  `{st.session_state.get('report_hash', '')}`")
                st.download_button(
                    "Download PDF report", data=Path(st.session_state.report_path).read_bytes(),
                    file_name="proofpath-vapt-report.pdf", mime="application/pdf",
                    use_container_width=True,
                )
                sarif_f = Path(st.session_state.get("sarif_path", ""))
                if sarif_f.is_file():
                    st.download_button(
                        "Export SARIF v2.1.0", data=sarif_f.read_bytes(),
                        file_name="proofpath-assessment.sarif", mime="application/json",
                        use_container_width=True,
                    )
                cef_f = Path(st.session_state.get("cef_path", ""))
                if cef_f.is_file():
                    st.download_button(
                        "Export SIEM (CEF)", data=cef_f.read_bytes(),
                        file_name="proofpath-assessment.cef", mime="text/plain",
                        use_container_width=True,
                    )

    st.divider()
    with st.expander("Retesting — Remediation Change Tracking"):
        st.caption("Upload a prior findings JSON baseline to compute new/persisting/remediated counts.")
        baseline_file = st.file_uploader("Prior findings (JSON)", type=["json"], key="baseline_findings_file")
        if baseline_file is not None:
            try:
                baseline_findings = [Finding.model_validate(i) for i in json.loads(baseline_file.getvalue().decode())]
                diff = compare_assessments(baseline_findings, findings_for_report)
                d1, d2, d3 = st.columns(3)
                d1.metric("New", diff.total_new)
                d2.metric("Persisting", diff.total_persisting)
                d3.metric("Remediated", diff.total_remediated)
                st.download_button(
                    "Download Delta JSON",
                    data=json.dumps(diff.to_dict(), indent=2).encode(),
                    file_name="proofpath-remediation-delta.json",
                    mime="application/json",
                )
            except Exception as exc:
                st.error("Error computing diff: " + str(exc))


# ===========================================================================
# TAB 9 — AI Assistant
# ===========================================================================
with tab_assistant:
    st.subheader("Conversational Security Assistant")
    st.caption(
        "Ask anything about your engagement in plain English. "
        "The assistant validates scope, recommends tools, explains findings, and guides every VAPT lifecycle stage. "
        "Powered by local Qwen 2.5 7B — grounded in your actual evidence, never fabricating."
    )

    # ── Suggested quick-start prompts (shown prominently when no conversation yet)
    if not st.session_state.transcript:
        st.markdown(
            '<div style="background:rgba(167,139,250,0.06);border:1px solid rgba(167,139,250,0.2);'
            'border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem;">'
            '<div style="font-size:0.8rem;font-weight:700;color:#a78bfa;margin-bottom:0.6rem;letter-spacing:0.06em;">✦ TRY THESE</div>'
            '<div style="font-size:0.83rem;color:#94a3b8;">Click any prompt to get started, or type your own below.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        demo_prompts = [
            ("🎯", "Assess 10.20.0.10 for web vulnerabilities", "reconnaissance"),
            ("🔍", "What are the most critical findings right now?", "status"),
            ("🛡️", "Is 10.20.0.10 authorized in this engagement?", "scope"),
            ("📋", "What should I do next in this assessment?", "planning"),
            ("⚠️", "Explain the high severity findings", "analysis"),
            ("📊", "Summarize the current risk posture", "risk"),
        ]
        cols = st.columns(3)
        for i, (icon, prompt, _) in enumerate(demo_prompts):
            if cols[i % 3].button(f"{icon} {prompt}", key=f"demo_prompt_{i}", use_container_width=True):
                _client = None
                try:
                    m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                    if m_cfg.model_tag.strip():
                        _client = OllamaClient(m_cfg)
                except Exception:
                    pass
                _assistant = SecurityAssistant(GUARD, AUDIT, LEDGER, model_client=_client)
                _reply = _assistant.parse_request(prompt, st.session_state.observations, st.session_state.raw_findings)
                st.session_state.transcript.append(f"Analyst: {prompt}")
                st.session_state.transcript.append(f"Assistant: {_reply.assistant_reply}")
                st.rerun()

    # ── Chat history
    if st.session_state.transcript:
        chat_html = (
            '<div style="border:1px solid rgba(255,255,255,0.08);border-radius:10px;'
            'padding:1rem;margin-bottom:1rem;max-height:380px;overflow-y:auto;">'
        )
        for line in st.session_state.transcript:
            if line.startswith("Analyst:"):
                chat_html += (
                    f'<div style="text-align:right;margin-bottom:0.6rem;">'
                    f'<span style="background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.2);'
                    f'border-radius:8px 8px 2px 8px;padding:6px 14px;font-size:0.84rem;color:#e2e8f0;'
                    f'display:inline-block;max-width:85%;text-align:left;">'
                    f'{line[8:].strip()}</span></div>'
                )
            else:
                content = line[10:].strip() if line.startswith("Assistant:") else line
                chat_html += (
                    f'<div style="margin-bottom:0.6rem;">'
                    f'<span style="display:inline-block;background:rgba(167,139,250,0.08);'
                    f'border:1px solid rgba(167,139,250,0.2);border-radius:2px 8px 8px 8px;'
                    f'padding:6px 14px;font-size:0.84rem;color:#e2e8f0;max-width:85%;">'
                    f'<span style="font-size:0.68rem;font-weight:700;color:#a78bfa;display:block;margin-bottom:3px;">✦ PROOFPATH AI</span>'
                    f'{content}</span></div>'
                )
        chat_html += "</div>"
        st.markdown(chat_html, unsafe_allow_html=True)

    # ── Input row
    query_col, btn_col = st.columns([5, 1])
    query = query_col.text_input(
        "Ask the assistant",
        placeholder="e.g. 'What are the critical findings?', 'Is 10.20.0.10 in scope?', 'What tool should I run next?'",
        key="conv_assistant_query",
        label_visibility="collapsed",
    )
    send_clicked = btn_col.button("Consult Assistant", key="btn_ask_assistant", type="primary", use_container_width=True)

    if send_clicked and query.strip():
        _client = None
        try:
            m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
            if m_cfg.model_tag.strip():
                _client = OllamaClient(m_cfg)
        except Exception:
            pass
        with st.spinner("✦ AI thinking…"):
            _assistant = SecurityAssistant(GUARD, AUDIT, LEDGER, model_client=_client)
            _reply = _assistant.parse_request(
                query.strip(), st.session_state.observations, st.session_state.raw_findings
            )
        st.session_state.transcript.append(f"Analyst: {query.strip()}")
        st.session_state.transcript.append(f"Assistant: {_reply.assistant_reply}")
        if _reply.scope_allowed is True:
            st.success(f"Scope check: {_reply.target} is authorized for testing.")
        elif _reply.scope_allowed is False:
            st.error(f"Scope check: {_reply.target} is denied — {_reply.scope_reason}")
        st.rerun()
    elif send_clicked:
        st.warning("Type a question first.")

    # ── Grounded Report Q&A — answers restricted to current findings, must cite evidence
    st.markdown("---")
    with st.expander("✦ Ask the Report — grounded Q&A (refuses uncited answers)", expanded=False):
        st.caption(
            "Answers are restricted to the current findings and must cite their evidence IDs. "
            "Any uncited or unverifiable claim is rejected and replaced with an evidence-only answer."
        )
        _rq = st.text_input(
            "Question about the current report",
            key="report_qa_query",
            placeholder="e.g. 'Which findings affect 10.20.0.10?' or 'Summarize the critical findings'",
            label_visibility="collapsed",
        )
        if st.button("Ask the report", key="btn_report_qa", type="primary") and _rq.strip():
            _qa_client = None
            try:
                _qa_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                if _qa_cfg.model_tag.strip():
                    _qa_client = OllamaClient(_qa_cfg)
            except Exception:
                pass
            with st.spinner("✦ Grounding the answer in ledger evidence…"):
                _qa_answer = answer_report_question(
                    _rq.strip(), merged_findings, st.session_state.observations, LEDGER, AUDIT,
                    model_client=_qa_client,
                )
            st.markdown(_qa_answer.answer)
            if _qa_answer.cited_evidence_ids:
                st.caption("Cited evidence: " + ", ".join(_qa_answer.cited_evidence_ids))
            if _qa_answer.grounded:
                st.success("Grounded — every claim cites ledger evidence.")
            else:
                st.warning("Grounding issues: " + "; ".join(_qa_answer.critique))
        elif not merged_findings:
            st.info("No findings are loaded yet. Scan or import a report first.")

    # ── Context awareness — show what the assistant knows
    if merged_findings or st.session_state.observations:
        st.markdown("---")
        ctx_cols = st.columns(4)
        ctx_cols[0].metric("Services discovered", len(st.session_state.observations))
        ctx_cols[1].metric("Correlated findings", len(merged_findings))
        ctx_cols[2].metric("Tools loaded", len(st.session_state.tool_ingestion_status) + (1 if st.session_state.observations else 0))
        critical_count = sum(1 for f in merged_findings if f.severity == "critical")
        ctx_cols[3].metric("Critical findings", critical_count, delta="requires action" if critical_count else None, delta_color="inverse")

    # ── Clear chat
    if st.session_state.transcript:
        if st.button("Clear conversation", key="clear_chat"):
            st.session_state.transcript = []
            st.rerun()


# ===========================================================================
# TAB 10 — Autonomous Agent
# ===========================================================================
with tab_agent:
    st.subheader("Autonomous VAPT Agent")
    st.caption(
        "ReAct-style orchestrator — Observe → Think (Qwen) → Act (scope-guarded) → Reflect. "
        "Runs iteratively until all candidates are exhausted or the step limit is reached."
    )

    if not st.session_state.agent_result:
        with st.expander("Agent Parameters", expanded=True):
            pa1, pa2 = st.columns(2)
            max_steps = pa1.slider("Max steps", 1, 50, 15, key="agent_max_steps")
            auto_nmap = pa1.checkbox(
                "Auto-execute live probes",
                value=False, key="agent_auto_nmap",
                help="Automatically executes live Nmap probes for authorized targets.",
            )
            pause_imports = pa2.checkbox(
                "Queue ingestion requests",
                value=True, key="agent_pause_imports",
                help="Queues tool import requests for analyst review instead of auto-running.",
            )
    else:
        max_steps = st.session_state.get("agent_max_steps", 15)
        auto_nmap = st.session_state.get("agent_auto_nmap", False)
        pause_imports = st.session_state.get("agent_pause_imports", True)

    if st.button("Start Autonomous Assessment", key="btn_run_agent", type="primary"):
        with st.spinner("Agent executing ReAct assessment loop…"):
            try:
                client = None
                try:
                    m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                    if m_cfg.model_tag.strip():
                        client = OllamaClient(m_cfg)
                except Exception:
                    pass
                from proofpath.threat_intel import PublicThreatIntel as _PTI
                _intel = _safe_intel()
                if not isinstance(_intel, _PTI):
                    _intel = None
                agent_config = AgentConfig(
                    max_steps=max_steps,
                    auto_execute_nmap=auto_nmap,
                    pause_for_imports=pause_imports,
                    model_client=client,
                    public_intel=_intel,
                    criticality=st.session_state.criticality_by_asset,
                )
                agent = VAPTAgent(GUARD, AUDIT, LEDGER, NMAP_ADAPTERS, agent_config)
                agent.load_state(
                    observations=st.session_state.observations,
                    findings=st.session_state.raw_findings,
                )
                result = agent.run()
                st.session_state.agent_result = result
                st.session_state.observations = agent.observations
                st.session_state.raw_findings = agent.raw_findings
                st.success(
                    f"Complete — Status: {result.status.upper()} · "
                    f"Steps: {len(result.steps)} · "
                    f"Duration: {result.duration_seconds:.1f}s"
                )
            except Exception as exc:
                st.error(f"Agent error: {exc}")

    agent_result = st.session_state.agent_result
    if agent_result is not None:
        st.divider()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Status", agent_result.status.replace("_", " ").upper())
        m2.metric("Steps", len(agent_result.steps))
        m3.metric("Services", agent_result.total_observations)
        m4.metric("Findings", agent_result.total_findings)
        m5, m6, m7, m8 = st.columns(4)
        m5.metric("Candidates evaluated", agent_result.total_candidates_evaluated)
        m6.metric("Pending imports", len(agent_result.import_requests))
        m7.metric("Duration", f"{agent_result.duration_seconds:.1f}s")
        m8.metric("Run ID", agent_result.run_id[:8])

        if agent_result.plan:
            with st.expander("Strategic Plan", expanded=True):
                st.write(agent_result.plan.reasoning)
                if agent_result.plan.targets:
                    st.caption("Targets: " + ", ".join(agent_result.plan.targets))
                if agent_result.plan.planned_actions:
                    st.caption("Planned: " + ", ".join(agent_result.plan.planned_actions))

        with st.expander("ReAct Execution Trace", expanded=True):
            for step in agent_result.steps:
                badge = step.step_type.value.upper()
                label = f"Step {step.step_number} · **[{badge}]**"
                if step.action_name:
                    label += f" · `{step.action_name}`"
                if step.target:
                    label += f" · {step.target}"
                    if step.ports:
                        label += f":{','.join(str(p) for p in step.ports)}"
                st.markdown(label)
                st.caption(step.reasoning)
                if step.decision_allowed is not None:
                    auth_str = "Authorized" if step.decision_allowed else "Denied"
                    st.caption(f"Scope: {auth_str}" + (f" · {step.decision_reason}" if step.decision_reason else ""))
                if step.evidence_id:
                    st.caption(f"Evidence: `{step.evidence_id}` · {step.tool_status}")
                if step.observations_added:
                    st.caption(f"New services: {step.observations_added}")
                st.markdown("---")

        if agent_result.import_requests:
            st.markdown("### Pending Tool Ingestion Requests")
            st.info("The agent identified gaps in tool coverage for these endpoints:")
            for req in agent_result.import_requests:
                port_str = ",".join(str(p) for p in req.ports)
                with st.expander(f"{req.tool} — {req.target}:{port_str}"):
                    st.write(f"**Tool:** {req.tool}")
                    st.write(f"**Target:** {req.target}:{port_str}")
                    st.write(f"**Why:** {req.reason}")
                    st.write(f"**Expected value:** {req.expected_result}")

        st.download_button(
            "Export Agent Trace JSON",
            data=agent_result.model_dump_json(indent=2).encode(),
            file_name="proofpath-agent-trace.json",
            mime="application/json",
            key="download_agent_trace",
        )
        if st.button("Reset agent", key="reset_agent"):
            st.session_state.agent_result = None
            st.rerun()
