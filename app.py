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
from proofpath.audit import AuditLog
from proofpath.approval import decide_approval, request_approval
from proofpath.correlator import correlate_findings
from proofpath.integrations import INTEGRATIONS
from proofpath.grounding import verify_finding, verify_text
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

st.set_page_config(page_title="ProofPath | Enterprise VAPT Console", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(ellipse at 15% 0%, #0d1527 0%, #070b14 42%, #05080f 100%); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }
    .block-container { max-width: 1540px; padding-top: 1.2rem; padding-bottom: 2.8rem; }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stSidebar"] { background: #0a0f1d; border-right: 1px solid #1a233a; }
    [data-testid="stMetric"] { background: linear-gradient(145deg, #10192e, #0a1120); border: 1px solid #1e2c48; border-radius: 10px; padding: 0.75rem 0.95rem; }
    [data-testid="stMetricLabel"] { color: #8fa0bd; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
    [data-testid="stMetricValue"] { color: #f1f5f9; font-weight: 700; }
    div[data-baseweb="tab-list"] { gap: 0.35rem; border-bottom: 1px solid #1e293b; }
    button[data-baseweb="tab"] { border-radius: 8px 8px 0 0; padding: 0.6rem 0.95rem; font-weight: 600; font-size: 0.86rem; color: #94a3b8; }
    button[data-baseweb="tab"][aria-selected="true"] { color: #38bdf8; background: #0f172a; border-top: 2px solid #0284c7; }
    div.stButton > button, button[kind="primaryFormSubmit"] { border-radius: 8px; min-height: 2.5rem; font-weight: 600; letter-spacing: 0.02em; }
    [data-testid="stExpander"] { border: 1px solid #1e293b; border-radius: 10px; background: #0c1222; }
    .pp-header { border: 1px solid #1e293b; border-radius: 14px; padding: 1.25rem 1.6rem; margin: 0.2rem 0 1rem; background: linear-gradient(135deg, rgba(15,23,42,0.95), rgba(10,15,29,0.95)); box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
    .pp-kicker { color: #38bdf8; font-size: 0.72rem; font-weight: 750; letter-spacing: 0.14em; text-transform: uppercase; }
    .pp-header h1 { color: #f8fafc; font-size: 1.85rem; font-weight: 750; line-height: 1.15; margin: 0.25rem 0 0.35rem; letter-spacing: -0.02em; }
    .pp-header p { color: #94a3b8; font-size: 0.92rem; margin: 0; max-width: 950px; line-height: 1.45; }
    .pp-status-badge { display: inline-flex; align-items: center; border: 1px solid #0284c7; color: #38bdf8; background: rgba(2,132,199,0.14); border-radius: 6px; padding: 0.2rem 0.65rem; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em; margin-top: 0.65rem; }
    .badge-crit { background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid #ef4444; border-radius: 4px; padding: 2px 7px; font-size: 0.75rem; font-weight: 700; }
    .badge-high { background: rgba(249,115,22,0.18); color: #fb923c; border: 1px solid #f97316; border-radius: 4px; padding: 2px 7px; font-size: 0.75rem; font-weight: 700; }
    .badge-med { background: rgba(234,179,8,0.18); color: #facc15; border: 1px solid #eab308; border-radius: 4px; padding: 2px 7px; font-size: 0.75rem; font-weight: 700; }
    .badge-low { background: rgba(59,130,246,0.18); color: #60a5fa; border: 1px solid #3b82f6; border-radius: 4px; padding: 2px 7px; font-size: 0.75rem; font-weight: 700; }
    .badge-info { background: rgba(148,163,184,0.18); color: #cbd5e1; border: 1px solid #94a3b8; border-radius: 4px; padding: 2px 7px; font-size: 0.75rem; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

GUARD = ScopeGuard.from_yaml(SCOPE_CONFIG_PATH)
AUDIT = AuditLog(DATA_ROOT / "audit.jsonl")
LEDGER = Ledger(DATA_ROOT / "evidence")
NMAP_CONFIG = NmapExecutionConfig.from_yaml(ROOT / "nmap.yaml")
NMAP_ADAPTERS = {
    ActionName.NMAP_SCAN: NmapAdapter(
        wsl_distribution=NMAP_CONFIG.distribution if NMAP_CONFIG.runtime == "wsl" else None
    )
}

def _ports(text: str) -> list[int]:
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not parts:
        raise ValueError("ports are required")
    ports: list[int] = []
    for part in parts:
        if not part.isdigit():
            raise ValueError("ports must be a comma-separated list of integers")
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError("ports must be between 1 and 65535")
        ports.append(port)
    return ports


def _append_findings(findings: list[Finding]) -> None:
    st.session_state.raw_findings.extend(findings)


def _audit_grounding_rejection(key: str, details: dict[str, object]) -> None:
    seen = st.session_state.setdefault("grounding_rejections", set())
    if key not in seen:
        AUDIT.append("grounding_rejected", "grounding-verifier", details)
        seen.add(key)


def _import_failure(tool: str, filename: str, raw: bytes, error: Exception) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return (
        f"Tool: {tool} · filename: {filename} · SHA-256: {digest} · evidence ID: none · "
        f"source_mode=imported · parsed: 0 · dropped out of scope: 0 · parse errors: 1 · error: {error}"
    )


def _show_finding_table(findings: list[Finding]) -> None:
    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    low_count = sum(1 for f in findings if f.severity == "low")
    info_count = sum(1 for f in findings if f.severity in {"info", "not_provided"})

    st.markdown(
        f'<div style="display:flex; gap:12px; margin-bottom:12px; align-items:center;">'
        f'<span class="badge-crit">Critical: {crit_count}</span>'
        f'<span class="badge-high">High: {high_count}</span>'
        f'<span class="badge-med">Medium: {med_count}</span>'
        f'<span class="badge-low">Low: {low_count}</span>'
        f'<span class="badge-info">Info: {info_count}</span>'
        f'<span style="color:#64748b; font-size:0.8rem; margin-left:auto;">Total Correlated: {len(findings)}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    rows = [
        {
            "Title": item.title,
            "Asset": item.asset.ip,
            "Port": item.port,
            "Protocol": item.protocol,
            "Severity": item.severity.upper(),
            "Confidence": item.confidence.title(),
            "Status": item.status.replace("_", " ").title(),
            "Sources": ", ".join(item.source_tools),
            "Evidence IDs": ", ".join(dict.fromkeys(ref.evidence_id for ref in item.evidence)),
        }
        for item in findings
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)
    for index, finding in enumerate(findings, 1):
        with st.expander(f"Finding {index}: {finding.title} — {finding.asset.ip}:{finding.port} [{finding.severity.upper()}]"):
            c1, c2 = st.columns([3, 2])
            with c1:
                st.markdown("**Observed Evidence**")
                st.text(finding.observed)
                if finding.inference:
                    grounding = verify_finding(finding, LEDGER)
                    if grounding.accepted:
                        st.markdown("**AI Inference**")
                        st.text(finding.inference)
                    else:
                        _audit_grounding_rejection(f"finding:{finding.id}:{hash(finding.inference)}", {"finding_id": finding.id, "evidence_ids": [ref.evidence_id for ref in finding.evidence], "violations": list(grounding.violations), "fallback": "AI inference hidden"})
                        st.warning("AI inference rejected by grounding verifier: " + "; ".join(grounding.violations))
                if finding.conflict_notes:
                    st.warning("Cross-Tool Discrepancies: " + " | ".join(finding.conflict_notes))
            with c2:
                st.markdown("**Technical Attributes**")
                st.text(f"CVEs: {', '.join(finding.cves) if finding.cves else 'None reported'}")
                st.text(f"CWEs: {', '.join(finding.cwes) if finding.cwes else 'None reported'}")
                st.text(f"CVSS Score: {finding.cvss if finding.cvss is not None else 'not provided'}")
                st.text(f"Validation State: {finding.validation_status}")
            st.markdown("**Cited Ledger Artifacts**")
            for ref in finding.evidence:
                st.markdown(f"**Evidence Ref:** `{ref.evidence_id}` · Location: `{ref.locator}`")
                st.code(ref.excerpt or "No excerpt available", language="xml")


with st.sidebar:
    st.markdown("### Engagement Scope")
    st.text(f"ID: {GUARD.policy.engagement}")
    st.text("Allowed: " + ", ".join(GUARD.policy.allowed_cidrs))
    st.text("Excluded: " + (", ".join(GUARD.policy.excluded_hosts) or "None"))
    st.text("Ports: " + ", ".join(GUARD.policy.allowed_ports))
    st.text("Engine: " + (f"WSL ({NMAP_CONFIG.distribution})" if NMAP_CONFIG.runtime == "wsl" else "Native"))

    st.markdown("---")
    st.markdown("### Quick Demo Setup")
    if st.button("Load Full 7-Tool Assessment", key="sidebar_load_demo", use_container_width=True, type="primary"):
        try:
            fixture = ROOT / "tests" / "fixtures" / "demo"
            demo_nmap = (fixture / "nmap.xml").read_bytes()
            demo_req = Action(id="demo-nmap-init", name=ActionName.IMPORT_NMAP_XML, target="10.20.0.10", ports=[80], engagement_id=GUARD.policy.engagement, requested_by="analyst")
            res = execute_action(demo_req, GUARD, AUDIT, LEDGER, {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(demo_nmap)})
            st.session_state.observations = list(res.services)

            raw_f: list[Finding] = []
            if (fixture / "nessus.nessus").is_file():
                raw_f.extend(import_nessus_xml((fixture / "nessus.nessus").read_bytes(), GUARD, AUDIT, LEDGER).findings)
            if (fixture / "burp.xml").is_file():
                raw_f.extend(import_burp_xml((fixture / "burp.xml").read_bytes(), GUARD, AUDIT, LEDGER).findings)
            if (fixture / "openvas.xml").is_file():
                raw_f.extend(import_openvas_xml((fixture / "openvas.xml").read_bytes(), GUARD, AUDIT, LEDGER).findings)
            if (fixture / "nikto.json").is_file():
                raw_f.extend(import_nikto_report((fixture / "nikto.json").read_bytes(), GUARD, AUDIT, LEDGER).findings)
            if (fixture / "zap.xml").is_file():
                raw_f.extend(import_zap_report((fixture / "zap.xml").read_bytes(), GUARD, AUDIT, LEDGER).findings)
            if (fixture / "metasploit.xml").is_file():
                raw_f.extend(import_metasploit_report((fixture / "metasploit.xml").read_bytes(), GUARD, AUDIT, LEDGER).findings)

            st.session_state.raw_findings = raw_f
            st.success(f"Loaded {len(st.session_state.observations)} services & {len(raw_f)} tool findings across 7 adapters.")
            st.rerun()
        except Exception as exc:
            st.error(f"Error loading demo: {exc}")

    st.markdown("---")
    st.markdown("### Tool Capabilities")
    st.dataframe([{"Tool": row["tool"], "Mode": row["mode"]} for row in INTEGRATIONS], hide_index=True, use_container_width=True)

    st.markdown("---")
    st.markdown("### AI Engine Status")
    try:
        model_config = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
        st.text(f"Model: {model_config.model_tag or 'qwen2.5:7b'}")
        if st.button("Check AI Engine Status", key="warmup_qwen", use_container_width=True):
            try:
                OllamaClient(model_config).warmup()
                AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": model_config.model_tag, "status": "ok"})
                st.session_state.ollama_warmup_status = "AI Engine is operational."
            except Exception as exc:
                AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": model_config.model_tag, "status": "unavailable", "reason": str(exc)[:500]})
                st.session_state.ollama_warmup_status = "AI Engine offline; using deterministic rule planner."
        if st.session_state.get("ollama_warmup_status"):
            st.caption(st.session_state.ollama_warmup_status)
    except Exception as exc:
        st.caption(f"Config: {exc}")

if "raw_findings" not in st.session_state:
    st.session_state.raw_findings = []
if "observations" not in st.session_state:
    st.session_state.observations = []
if "transcript" not in st.session_state:
    st.session_state.transcript = []
if "plan_proposal" not in st.session_state:
    st.session_state.plan_proposal = None
if "plan_status" not in st.session_state:
    st.session_state.plan_status = ""
if "plan_metrics" not in st.session_state:
    st.session_state.plan_metrics = []
if "criticality_by_asset" not in st.session_state:
    st.session_state.criticality_by_asset = {}
if "approval_records" not in st.session_state:
    st.session_state.approval_records = {}
if "report_path" not in st.session_state:
    st.session_state.report_path = ""
if "public_threat_intel" not in st.session_state:
    try:
        st.session_state.public_threat_intel = load_public_threat_intel(DATA_ROOT / "threat_intel" / "training", LEDGER)
        st.session_state.public_threat_intel_error = ""
    except Exception as exc:
        st.session_state.public_threat_intel = None
        st.session_state.public_threat_intel_error = str(exc)[:300]
if "agent_result" not in st.session_state:
    st.session_state.agent_result = None
if "agent_running" not in st.session_state:
    st.session_state.agent_running = False

model_configured = False
try:
    model_configured = bool(OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH).model_tag.strip())
except Exception:
    pass

st.markdown(
    """
    <section class="pp-header">
      <div class="pp-kicker">Enterprise Security Assessment & Pentesting Console</div>
      <h1>ProofPath VAPT Platform</h1>
      <p>Automated, auditable vulnerability assessment and penetration testing system. Enforces strict scope boundaries, multi-tool report correlation, evidence-grounded AI reasoning, and hash-chained audit integrity.</p>
      <span class="pp-status-badge">SCOPE GUARD ACTIVE · DETERMINISTIC GATE CHOKEPOINT</span>
    </section>
    """,
    unsafe_allow_html=True,
)

status_cols = st.columns(4)
status_cards = [
    ("Engagement", GUARD.policy.engagement),
    ("Authorized Subnets", f"{len(GUARD.policy.allowed_cidrs)} CIDR range(s)"),
    ("Execution Engine", f"WSL {NMAP_CONFIG.distribution}" if NMAP_CONFIG.runtime == "wsl" else "Native"),
    ("Reasoning Model", "Qwen 2.5 7B (Local)" if model_configured else "Active (Local)"),
]
for column, (label, value) in zip(status_cols, status_cards):
    column.metric(label, value)

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
    active_stage = 6
elif has_obs:
    active_stage = 4
elif has_plan:
    active_stage = 2
else:
    active_stage = 1

stages = [
    ("1. Request", 1),
    ("2. Planning", 2),
    ("3. Scanning", 3),
    ("4. Ingestion", 4),
    ("5. Analysis", 5),
    ("6. Risk Ranking", 6),
    ("7. Authorization", 7),
    ("8. VAPT Report", 8),
]
stepper_html = '<div style="display:flex; justify-content:space-between; margin:0.6rem 0 1.2rem; gap:6px; font-size:0.75rem;">'
for label, num in stages:
    bg = "#0d281e" if num < active_stage else ("#132b45" if num == active_stage else "#0b1220")
    border = "#059669" if num < active_stage else ("#0284c7" if num == active_stage else "#1e293b")
    color = "#34d399" if num < active_stage else ("#f8fafc" if num == active_stage else "#64748b")
    indicator = "[DONE] " if num < active_stage else ("[ACTIVE] " if num == active_stage else "")
    stepper_html += f'<div style="flex:1; text-align:center; padding:0.45rem 0.2rem; background:{bg}; border:1px solid {border}; border-radius:6px; color:{color}; font-weight:600;">{indicator}{label}</div>'
stepper_html += '</div>'
st.markdown(stepper_html, unsafe_allow_html=True)

tabs = st.tabs([
    "Reconnaissance",
    "Findings",
    "Adaptive Plan",
    "Tool Ingestion",
    "Risk Prioritization",
    "Validation Approvals",
    "Executive Report",
    "Security Assistant",
    "Autonomous Agent",
])

# ---------------------------------------------------------------------------
# Tab 1: Reconnaissance
# ---------------------------------------------------------------------------
with tabs[0]:
    st.subheader("Target Reconnaissance & Service Discovery")
    with st.form("assess"):
        f_c1, f_c2 = st.columns([3, 1])
        with f_c1:
            request = st.text_input("Operational Objective", value="Network service enumeration and banner reconnaissance", placeholder="Enumerate open services on lab host")
            target = st.text_input("Target Host or Domain", value="10.20.0.10" if st.session_state.observations else "", placeholder="e.g. 10.10.1.5 or 10.20.0.10")
        with f_c2:
            ports_text = st.text_input("Target Ports", value="80,443,8080,8443")
            skip_host_discovery = st.checkbox("Disable Ping (-Pn)", value=True)
            source_mode = st.radio("Execution Source", ["Live scan", "Import recorded XML"], horizontal=True)
        uploaded_xml = st.file_uploader("Recorded Nmap XML", type=["xml"]) if source_mode.startswith("Import") else None
        submitted = st.form_submit_button("Execute Scoped Reconnaissance", type="primary")

    if submitted:
        request_text = request.strip()
        target_text = target.strip()
        if not request_text or not target_text:
            st.error("Operational objective and target are both required.")
        else:
            AUDIT.append("analyst_request", "analyst", {"request": request_text[:500], "target": target_text, "ports": ports_text})
            try:
                ports = _ports(ports_text)
                if source_mode.startswith("Import") and uploaded_xml is None:
                    raise ValueError("Select a recorded Nmap XML file to import.")
                if source_mode.startswith("Import") and len(uploaded_xml.getvalue()) > MAX_IMPORT_BYTES:
                    raise ValueError(f"Upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                action = Action(
                    id=uuid.uuid4().hex,
                    name=ActionName.NMAP_SCAN,
                    target=target_text,
                    ports=ports,
                    arguments={
                        "service_detection": True,
                        "skip_host_discovery": skip_host_discovery,
                        "timing": 2,
                        "host_timeout_seconds": 60,
                    },
                    engagement_id=GUARD.policy.engagement,
                    requested_by="analyst",
                )
                if source_mode.startswith("Import"):
                    action.name = ActionName.IMPORT_NMAP_XML
                    adapters = {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(uploaded_xml.getvalue())}
                else:
                    adapters = NMAP_ADAPTERS
                result = execute_action(action, GUARD, AUDIT, LEDGER, adapters)
                source_label = "imported" if source_mode.startswith("Import") else "live"
                if source_label == "imported" and result.status == "error":
                    AUDIT.append("import_parse_error", "analyst", {"tool": "nmap", "filename": uploaded_xml.name, "source_mode": "imported", "error": result.message[:500]})
                
                col_r1, col_r2, col_r3 = st.columns(3)
                col_r1.metric("Scope Authorization", "Authorized" if result.decision.allowed else "Denied")
                col_r2.metric("Execution Status", result.status.upper())
                col_r3.metric("Evidence Artifact", result.evidence_id or "None")

                st.write(f"Scope allowed: **{result.decision.allowed}**")
                st.write(f"Reason: {result.decision.reason}")
                st.write(f"Status: `{result.status}` · source mode: **{source_label}**")
                st.write(f"Evidence ID: `{result.evidence_id or 'none'}`")

                if not result.decision.allowed:
                    st.error(f"Execution Denied by Scope Guard: {result.decision.reason}")
                else:
                    st.success(f"Scope Verified: {result.decision.reason}")

                if result.services:
                    st.session_state.observations.extend(result.services)
                    st.markdown("### Discovered Services")
                    st.dataframe([row.model_dump() for row in result.services], hide_index=True, use_container_width=True)
                else:
                    st.info("No active ports discovered for the specified range.")
            except ValueError as exc:
                st.error(str(exc))

    if st.session_state.observations:
        st.markdown("### Active Inventory Services")
        st.dataframe([row.model_dump() for row in st.session_state.observations], hide_index=True, use_container_width=True)

# ---------------------------------------------------------------------------
# Tab 2: Findings
# ---------------------------------------------------------------------------
with tabs[1]:
    st.subheader("Correlated Vulnerability Findings")
    updated_findings: list[Finding] = []
    for raw_finding in st.session_state.raw_findings:
        updated = apply_observation_evidence(raw_finding, st.session_state.observations)
        if updated.status != raw_finding.status:
            new_refs = [ref.model_dump(mode="json") for ref in updated.evidence if ref not in raw_finding.evidence]
            AUDIT.append("skeptic_status_updated", "skeptic", {"finding_id": updated.id, "old_status": raw_finding.status, "new_status": updated.status, "evidence": new_refs})
        updated_findings.append(updated)
    st.session_state.raw_findings = updated_findings
    merged_findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    if merged_findings:
        _show_finding_table(merged_findings)
        st.markdown("### Skeptic Validation Hypotheses")
        for item in analyze_findings(merged_findings, st.session_state.observations, GUARD.policy.engagement):
            with st.container():
                st.markdown(f"**Hypothesis [{item.hypothesis.id}]**: {item.hypothesis.statement}")
                st.caption("Supporting Evidence: " + (", ".join(ref.evidence_id for ref in item.hypothesis.evidence_for) or "None") + " · Refuting Evidence: " + (", ".join(ref.evidence_id for ref in item.hypothesis.evidence_against) or "None"))
                st.caption("Reasoning: " + item.planner_reason)
                if st.button("Gate Verification Recheck", key="skeptic_" + item.hypothesis.id):
                    try:
                        result = gate_recheck_proposal(item, GUARD, AUDIT, LEDGER)
                        st.info("Recheck Proposal: " + result.status + " · " + result.message)
                    except Exception as exc:
                        st.error("Error staging proposal: " + str(exc))
    else:
        st.info("No vulnerability findings currently imported. Ingest scanner reports in the Tool Ingestion tab or use the Quick Demo Setup.")

# ---------------------------------------------------------------------------
# Tab 3: Adaptive Plan
# ---------------------------------------------------------------------------
with tabs[2]:
    st.subheader("AI-Driven Adaptive Assessment Planning")
    executed = executed_fingerprints(AUDIT)
    candidates, skipped_candidates = RulePlanner().evaluate(
        st.session_state.observations,
        GUARD.policy.engagement,
        executed=executed,
        findings=merged_findings,
        criticality=st.session_state.criticality_by_asset,
        enabled_actions=set(GUARD.policy.enabled_actions),
        public_intel=st.session_state.public_threat_intel,
    )
    if not candidates:
        st.info("All assessment candidates for current observations have been executed or evaluated.")
    else:
        st.markdown(f"**Available Next Steps ({len(candidates)} candidates evaluated across 7 security tools):**")
        for candidate in candidates[:8]:
            with st.expander(f"{candidate.candidate_id} · {candidate.action.name.value.upper()} on {candidate.action.target}:{','.join(str(p) for p in candidate.action.ports)}"):
                st.write(candidate.planner_reason)
                st.caption(f"Exposure State: {candidate.exposure_state} · Evidence: {', '.join(candidate.observed_evidence_ids) or 'None'} · Priority Score: {candidate.risk_score if candidate.risk_score is not None else 'Unscored'}")
                st.caption("Expected Result: " + candidate.expected_result)

        if st.button("Generate plan", key="generate_plan", type="primary"):
            try:
                configured = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                client = OllamaClient(configured)
                metrics_start = len(client.metrics_history)
                proposal, result, used_fallback = propose_and_gate(
                    st.session_state.observations,
                    candidates,
                    client,
                    GUARD,
                    AUDIT,
                    LEDGER,
                    findings=merged_findings,
                )
                st.session_state.plan_proposal = proposal
                st.session_state.plan_candidate_context = next(
                    (item for item in candidates if proposal and item.candidate_id == proposal.candidate_id),
                    None,
                )
                st.session_state.plan_status = result.status if result else ""
                st.session_state.plan_candidate_count = len(candidates)
                st.session_state.plan_fallback = used_fallback
                st.session_state.plan_metrics = client.metrics_history[metrics_start:]
                st.session_state.plan_run_result = None
            except Exception as exc:
                AUDIT.append("proposer_unavailable", "model-proposer", {"reason": str(exc)[:500]})
                proposal, result, used_fallback = propose_and_gate(
                    st.session_state.observations,
                    candidates,
                    None,
                    GUARD,
                    AUDIT,
                    LEDGER,
                    findings=merged_findings,
                )
                st.session_state.plan_proposal = proposal
                st.session_state.plan_candidate_context = next(
                    (item for item in candidates if proposal and item.candidate_id == proposal.candidate_id),
                    None,
                )
                st.session_state.plan_status = result.status if result else ""
                st.session_state.plan_candidate_count = len(candidates)
                st.session_state.plan_fallback = used_fallback
                st.session_state.plan_metrics = []
                st.session_state.plan_run_result = None
                st.warning("Proposer unavailable: deterministic top rule-ranked candidate shown")

    proposal = st.session_state.plan_proposal
    if proposal is not None:
        selected_candidate = st.session_state.get("plan_candidate_context") or next(
            (item for item in candidates if item.action == proposal.action),
            None,
        )
        st.markdown("---")
        st.markdown("### Selected Strategic Operation")
        st.markdown(f"**Action:** `{proposal.action.name.value}` · **Target:** `{proposal.action.target}` · **Ports:** `{proposal.action.ports}`")
        
        c_tr1, c_tr2 = st.columns(2)
        with c_tr1:
            st.markdown("**Decision trace (code generated)**")
            if selected_candidate is not None:
                st.write(f"Trigger: {selected_candidate.planner_reason}")
                st.write(f"Expected result: {selected_candidate.expected_result}")
            if proposal.action.name == ActionName.NMAP_SCAN:
                st.write("Next operation: a one-port Nmap TCP connect recheck.")
            st.caption(f"Status: {st.session_state.plan_status.upper()}")
        with c_tr2:
            st.markdown("**Observed facts (code generated)**")
            st.markdown("**Model Reasoning & Rationale**")
            st.write("Observed: " + " ".join(proposal.rationale.observed))
            st.write("Inference: " + proposal.rationale.inferred)
            st.write("Strategic Justification: " + proposal.rationale.why)

        if st.session_state.plan_status == "planned":
            btn_col1, btn_col2 = st.columns(2)
            if btn_col1.button("Authorize Operation", key="approve_plan", type="primary"):
                checked = execute_action(
                    proposal.action,
                    GUARD,
                    AUDIT,
                    LEDGER,
                    {proposal.action.name: ProposalGateAdapter(candidate_match=True, proposal=proposal)},
                )
                if checked.decision.allowed:
                    follow_up = f"Operation {proposal.action.name.value} authorized for execution."
                    AUDIT.append("plan_approved", "analyst", {"action_id": proposal.action.id, "note": follow_up})
                    st.session_state.plan_status = "approved"
                    st.success(follow_up)
                else:
                    st.error("Scope authorization failed: " + checked.message)
            if btn_col2.button("Skip Action", key="skip_plan"):
                AUDIT.append("plan_skipped", "analyst", {"action_id": proposal.action.id})
                st.session_state.plan_status = "skipped"
                st.info("Action skipped.")

        if st.session_state.plan_status == "approved" and proposal.action.name == ActionName.NMAP_SCAN:
            if st.button("Execute Verification Probe", key="run_plan_nmap", type="primary"):
                analyst_action = proposal.action.model_copy(update={"requested_by": "analyst"})
                result = execute_action(analyst_action, GUARD, AUDIT, LEDGER, NMAP_ADAPTERS)
                if result.services:
                    st.session_state.observations.extend(result.services)
                st.success(f"Execution complete: status={result.status}, evidence={result.evidence_id}")

# ---------------------------------------------------------------------------
# Tab 4: Tool Ingestion
# ---------------------------------------------------------------------------
with tabs[3]:
    st.subheader("Security Tool Report Ingestion")
    st.caption("Parses, validates, hashes, and ingests reports across all 7 supported security assessment tools.")

    left, right = st.columns(2)
    with left:
        nessus_file = st.file_uploader("Nessus Report (.nessus XML)", type=["nessus", "xml"], key="nessus_import_file")
        if st.button("Ingest Nessus Report", key="import_nessus"):
            if nessus_file is None:
                st.error("Select a .nessus file.")
            else:
                raw = nessus_file.getvalue()
                try:
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    res = import_nessus_xml(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"Tool: Nessus · filename: {nessus_file.name} · SHA-256: {res.sha256} · evidence ID: {res.evidence_id} · source_mode=imported · parsed: {res.parsed_items} · dropped out of scope: {res.dropped_items} · parse errors: 0")
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "nessus", "filename": nessus_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Nessus", nessus_file.name, raw, exc))
    with right:
        burp_file = st.file_uploader("Burp Suite Export (XML)", type=["xml"], key="burp_import_file")
        if st.button("Ingest Burp Suite Report", key="import_burp"):
            if burp_file is None:
                st.error("Select a Burp Suite XML export.")
            else:
                raw = burp_file.getvalue()
                try:
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    res = import_burp_xml(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"Tool: Burp · filename: {burp_file.name} · SHA-256: {res.sha256} · evidence ID: {res.evidence_id} · source_mode=imported · parsed: {res.parsed_items} · dropped out of scope: {res.dropped_issues} · parse errors: 0")
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "burp", "filename": burp_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Burp", burp_file.name, raw, exc))

    st.markdown("---")
    left2, right2 = st.columns(2)
    with left2:
        openvas_file = st.file_uploader("OpenVAS / Greenbone Report (XML)", type=["xml"], key="openvas_import_file")
        if st.button("Ingest OpenVAS Report", key="import_openvas"):
            if openvas_file is not None:
                try:
                    res = import_openvas_xml(openvas_file.getvalue(), GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"OpenVAS ingested: {res.parsed_items} findings parsed, evidence: {res.evidence_id}")
                except Exception as exc:
                    st.error(f"Error parsing OpenVAS file: {exc}")
    with right2:
        nikto_file = st.file_uploader("Nikto Web Server Report (JSON/XML)", type=["json", "xml"], key="nikto_import_file")
        if st.button("Ingest Nikto Report", key="import_nikto"):
            if nikto_file is not None:
                try:
                    res = import_nikto_report(nikto_file.getvalue(), GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"Nikto ingested: {res.parsed_items} findings parsed, evidence: {res.evidence_id}")
                except Exception as exc:
                    st.error(f"Error parsing Nikto file: {exc}")

    st.markdown("---")
    left3, right3 = st.columns(2)
    with left3:
        zap_file = st.file_uploader("OWASP ZAP Report (XML/JSON)", type=["xml", "json"], key="zap_import_file")
        if st.button("Ingest OWASP ZAP Report", key="import_zap"):
            if zap_file is not None:
                try:
                    res = import_zap_report(zap_file.getvalue(), GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"OWASP ZAP ingested: {res.parsed_items} alerts parsed, evidence: {res.evidence_id}")
                except Exception as exc:
                    st.error(f"Error parsing ZAP file: {exc}")
    with right3:
        metasploit_file = st.file_uploader("Metasploit Verification Export (XML/JSON)", type=["xml", "json"], key="metasploit_import_file")
        if st.button("Ingest Metasploit Report", key="import_metasploit"):
            if metasploit_file is not None:
                try:
                    res = import_metasploit_report(metasploit_file.getvalue(), GUARD, AUDIT, LEDGER)
                    _append_findings(res.findings)
                    st.success(f"Metasploit verification ingested: {res.parsed_items} findings, evidence: {res.evidence_id}")
                except Exception as exc:
                    st.error(f"Error parsing Metasploit file: {exc}")

# ---------------------------------------------------------------------------
# Tab 5: Risk Prioritization
# ---------------------------------------------------------------------------
with tabs[4]:
    st.subheader("Multi-Factor Risk Prioritization Engine")
    public_intel = st.session_state.public_threat_intel
    if public_intel:
        st.caption(f"Verified Threat Feeds Active: CISA KEV ({public_intel.kev_evidence_id}) · FIRST EPSS ({public_intel.epss_evidence_id})")
    
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    if findings:
        assets = sorted({item.asset.ip for item in findings})
        st.markdown("**Asset Criticality Matrix**")
        crit_cols = st.columns(min(len(assets), 4))
        for i, asset in enumerate(assets):
            col = crit_cols[i % len(crit_cols)]
            prev = st.session_state.criticality_by_asset.get(asset, "medium")
            sel = col.selectbox(f"Asset: {asset}", ["low", "medium", "high"], index=["low", "medium", "high"].index(prev), key="crit_" + asset)
            if sel != prev:
                st.session_state.criticality_by_asset[asset] = sel
                AUDIT.append("asset_criticality_changed", "analyst", {"asset": asset, "old": prev, "new": sel})

        ranked = rank_findings(findings, st.session_state.observations, st.session_state.criticality_by_asset, public_intel)
        if ranked:
            rows = []
            for item in ranked:
                factor_text = "; ".join(f"{factor.name}={factor.value} ({factor.source})" for factor in item.factors if factor.included)
                rows.append({
                    "Rank": item.rank,
                    "ID": item.finding.id,
                    "Asset": item.finding.asset.ip,
                    "Severity": item.finding.severity.upper(),
                    "CVSS": item.finding.cvss if item.finding.cvss is not None else "not provided",
                    "Status": item.status_label,
                    "Priority Score": round(item.priority_score, 1) if item.priority_score is not None else "N/A",
                    "Included Risk Factors": factor_text,
                })
            st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        st.info("Ingest findings to generate risk priority ranking.")

# ---------------------------------------------------------------------------
# Tab 6: Validation Approvals
# ---------------------------------------------------------------------------
with tabs[5]:
    st.subheader("Human Authorization Checkpoint")
    st.caption("Active exploitation or validation requires independent dual-key human approval before execution (Hard Rule #6).")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    web_findings = [item for item in findings if item.port in {80, 443, 8080, 8443} or (item.service or "").casefold() in {"http", "https"}]

    if web_findings:
        selected_finding = st.selectbox("Select Finding for Active Verification", web_findings, format_func=lambda item: f"{item.id} · {item.asset.ip}:{item.port} · {item.title}", key="approval_finding")
        with st.form("approval_request_form"):
            c_r1, c_r2, c_r3 = st.columns(3)
            with c_r1:
                requester = st.text_input("Lead Pentester Identity", value="lead-assessor")
            with c_r2:
                method = st.selectbox("HTTP Method", ["GET", "HEAD"])
            with c_r3:
                path_options = GUARD.policy.allowed_validation_paths or ["/"]
                path = st.selectbox("Allowlisted URI Path", path_options)
            justification = st.text_input("Validation Rationale", value="Confirm non-destructive web endpoint accessibility and service state")
            request_submitted = st.form_submit_button("Submit Authorization Request", type="primary")

        if request_submitted:
            try:
                action = Action(id=uuid.uuid4().hex, name=ActionName.ACTIVE_VALIDATE, target=selected_finding.asset.ip, ports=[selected_finding.port], arguments={"method": method, "path": path, "finding_id": selected_finding.id}, engagement_id=GUARD.policy.engagement, requested_by=requester.strip())
                scope_result = execute_action(action, GUARD, AUDIT, LEDGER, {})
                if "approval" in scope_result.message:
                    approval = request_approval(action, requester.strip(), justification)
                    st.session_state.approval_records[approval.id] = {"request": approval, "action": action}
                    AUDIT.append("approval_requested", requester.strip(), {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "action": action.model_dump(mode="json"), "justification": approval.justification, "expires_at": approval.expires_at.isoformat()})
                    st.success("Authorization request staged. Dual-key security protocol requires a distinct authorized user to sign off.")
                else:
                    st.error("Request denied by Scope Guard: " + scope_result.message)
            except Exception as exc:
                st.error("Authorization error: " + str(exc))

    approver = st.text_input("Authorizing Lead Identity", value="engagement-director", key="approval_approver")
    for approval_id, record in list(st.session_state.approval_records.items()):
        approval = record["request"]
        action = record["action"]
        st.markdown(f"**Request [{approval.id[:8]}]**: `{action.arguments['method']} {action.target}:{action.ports[0]}{action.arguments['path']}` · Requested by: `{approval.requested_by}` · State: `{approval.state.value.upper()}`")
        if approval.state.value == "pending":
            col_a1, col_a2 = st.columns(2)
            if col_a1.button("Authorize Verification Probe", key=f"app_{approval_id}", type="primary"):
                try:
                    decided = decide_approval(approval, approver, approved=True)
                    record["request"] = decided
                    AUDIT.append("approval_decision", approver, {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "decided_by": approver, "state": decided.state.value})
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
            if col_a2.button("Deny Request", key=f"deny_{approval_id}"):
                try:
                    decided = decide_approval(approval, approver, approved=False)
                    record["request"] = decided
                    AUDIT.append("approval_decision", approver, {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "decided_by": approver, "state": decided.state.value})
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
        elif approval.state.value == "approved" and approval.used_at is None:
            if st.button("Execute Authorized Probe Once", key="run_" + approval_id, type="primary"):
                try:
                    result = execute_action(action, GUARD, AUDIT, LEDGER, {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(action, approval)}, approval=approval)
                    record["request"] = approval.model_copy(update={"used_at": datetime.now(timezone.utc)})
                    st.success(f"Execution complete: {result.message}")
                    st.rerun()
                except Exception as exc:
                    st.error("Execution failed safely: " + str(exc))

# ---------------------------------------------------------------------------
# Tab 7: Executive Report
# ---------------------------------------------------------------------------
with tabs[6]:
    st.subheader("Executive & Technical Assessment Deliverables")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    if st.button("Generate Formal ReportLab PDF", disabled=not findings, type="primary"):
        try:
            report_dir = DATA_ROOT / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_result = generate_pdf(findings, st.session_state.observations, LEDGER, AUDIT, report_dir / "assessment.pdf", engagement=GUARD.policy.engagement, scope_cidrs=GUARD.policy.allowed_cidrs, criticality=st.session_state.criticality_by_asset, public_intel=st.session_state.public_threat_intel)
            st.session_state.report_path = report_result["path"]
            st.session_state.report_hash = report_result["sha256"]
            st.session_state.sarif_path = report_result.get("sarif_path", "")
            st.session_state.report_status = f"Grounded Findings: {report_result['grounded_findings']}/{report_result['total_findings']}"
            st.success("Report successfully generated and cryptographically hashed.")
        except Exception as exc:
            AUDIT.append("report_generation_failed", "analyst", {"reason": f"{type(exc).__name__}: {exc}"[:500]})
            st.error("Report generation error: " + str(exc))

    if st.session_state.report_path and Path(st.session_state.report_path).is_file():
        st.markdown(f"**Cryptographic SHA-256 Digest**: `{st.session_state.report_hash}`")
        dl_c1, dl_c2 = st.columns(2)
        with dl_c1:
            st.download_button("Download Formal PDF Report", data=Path(st.session_state.report_path).read_bytes(), file_name="proofpath-vapt-report.pdf", mime="application/pdf", use_container_width=True)
        with dl_c2:
            sarif_file = Path(st.session_state.get("sarif_path", ""))
            if sarif_file.is_file():
                st.download_button("Export OASIS SARIF v2.1.0", data=sarif_file.read_bytes(), file_name="proofpath-assessment.sarif", mime="application/json", use_container_width=True)

    st.markdown("---")
    with st.expander("Retesting & Remediation Change Tracking"):
        st.caption("Upload prior baseline findings JSON to compute remediation diffs.")
        baseline_file = st.file_uploader("Prior Findings File (current-findings.json)", type=["json"], key="baseline_findings_file")
        if baseline_file is not None:
            try:
                raw_baseline = json.loads(baseline_file.getvalue().decode("utf-8"))
                baseline_findings = [Finding.model_validate(item) for item in raw_baseline]
                diff = compare_assessments(baseline_findings, findings)
                d1, d2, d3 = st.columns(3)
                d1.metric("New Findings", diff.total_new)
                d2.metric("Persisting Findings", diff.total_persisting)
                d3.metric("Verified Remediated", diff.total_remediated)
                st.download_button("Download Delta JSON", data=json.dumps(diff.to_dict(), indent=2).encode("utf-8"), file_name="proofpath-remediation-delta.json", mime="application/json")
            except Exception as exc:
                st.error("Error computing diff: " + str(exc))

# ---------------------------------------------------------------------------
# Tab 8: Security Assistant
# ---------------------------------------------------------------------------
with tabs[7]:
    st.subheader("Conversational Security Assistant")
    st.caption("Conversational AI interface grounded in Scope Guard boundaries and the 8-stage VAPT lifecycle.")
    query = st.text_input("Operational Query", placeholder="e.g. Assess 10.20.0.10 for web vulnerabilities, or check if 10.10.1.5 is in scope", key="conv_assistant_query")
    if st.button("Consult Assistant", key="btn_ask_assistant", type="primary"):
        if query.strip():
            client = None
            try:
                m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                if m_cfg.model_tag.strip():
                    client = OllamaClient(m_cfg)
            except Exception:
                pass
            assistant = SecurityAssistant(GUARD, AUDIT, LEDGER, model_client=client)
            reply = assistant.parse_request(query.strip(), st.session_state.observations, st.session_state.raw_findings)
            st.session_state.transcript.append(f"Analyst: {query.strip()}")
            st.session_state.transcript.append(f"Assistant: {reply.assistant_reply}")
            st.markdown(reply.assistant_reply)
            if reply.scope_allowed is True:
                st.success(f"Scope Verified: Target {reply.target} is authorized for testing.")
            elif reply.scope_allowed is False:
                st.error(f"Scope Alert: Target {reply.target} is denied by policy: {reply.scope_reason}")
        else:
            st.warning("Enter a query or assessment request.")

    if st.session_state.transcript:
        with st.expander("Session Conversation History"):
            for line in st.session_state.transcript:
                st.text(line)

# ---------------------------------------------------------------------------
# Tab 9: Autonomous Agent
# ---------------------------------------------------------------------------
with tabs[8]:
    st.subheader("Autonomous VAPT Agent")
    st.caption("Autonomous ReAct orchestrator that iteratively plans, executes, and reflects on security assessment steps through the Scope Guard choke point.")

    with st.expander("Agent Execution Parameters", expanded=not st.session_state.agent_result):
        agent_col1, agent_col2 = st.columns(2)
        with agent_col1:
            max_steps = st.slider("Step Limit", min_value=1, max_value=50, value=15, key="agent_max_steps")
            auto_nmap = st.checkbox("Auto-Execute Live Probes", value=False, key="agent_auto_nmap", help="Automatically executes live Nmap TCP connect probes for authorized targets.")
        with agent_col2:
            pause_imports = st.checkbox("Queue Ingestion Requests", value=True, key="agent_pause_imports", help="Queues requests for analyst-supplied reports for offline tools.")

    if st.button("Start Autonomous Assessment", key="btn_run_agent", type="primary"):
        with st.spinner("Executing ReAct assessment loop..."):
            try:
                client = None
                try:
                    m_cfg = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                    if m_cfg.model_tag.strip():
                        client = OllamaClient(m_cfg)
                except Exception:
                    pass

                agent_config = AgentConfig(
                    max_steps=max_steps,
                    auto_execute_nmap=auto_nmap,
                    pause_for_imports=pause_imports,
                    model_client=client,
                    public_intel=st.session_state.public_threat_intel,
                    criticality=st.session_state.criticality_by_asset,
                )

                agent = VAPTAgent(GUARD, AUDIT, LEDGER, NMAP_ADAPTERS, agent_config)
                agent.load_state(observations=st.session_state.observations, findings=st.session_state.raw_findings)
                result = agent.run()
                st.session_state.agent_result = result
                st.session_state.observations = agent.observations
                st.session_state.raw_findings = agent.raw_findings
                st.success(f"Assessment loop completed: Status={result.status.upper()} · Steps={len(result.steps)} · Duration={result.duration_seconds:.1f}s")
            except Exception as exc:
                st.error(f"Agent error: {exc}")

    agent_result = st.session_state.agent_result
    if agent_result is not None:
        st.markdown("---")
        st.markdown("### Execution Run Summary")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Status", agent_result.status.replace("_", " ").upper())
        m2.metric("Steps Executed", len(agent_result.steps))
        m3.metric("Discovered Services", agent_result.total_observations)
        m4.metric("Correlated Findings", agent_result.total_findings)

        m5, m6, m7, m8 = st.columns(4)
        m5.metric("Candidates Evaluated", agent_result.total_candidates_evaluated)
        m6.metric("Pending Ingestion Requests", len(agent_result.import_requests))
        m7.metric("Loop Duration", f"{agent_result.duration_seconds:.1f}s")
        m8.metric("Run ID", agent_result.run_id[:8])

        if agent_result.plan:
            with st.expander("Strategic Assessment Plan", expanded=True):
                st.write(agent_result.plan.reasoning)
                if agent_result.plan.targets:
                    st.caption("Target Scope: " + ", ".join(agent_result.plan.targets))
                if agent_result.plan.planned_actions:
                    st.caption("Planned Operations: " + ", ".join(agent_result.plan.planned_actions))

        with st.expander("ReAct Execution Trace", expanded=True):
            for step in agent_result.steps:
                badge = f"[{step.step_type.value.upper()}]"
                step_label = f"Step {step.step_number} · **{badge}**"
                if step.action_name:
                    step_label += f" · `{step.action_name}`"
                if step.target:
                    step_label += f" · {step.target}"
                if step.ports:
                    step_label += f":{','.join(str(p) for p in step.ports)}"

                st.markdown(step_label)
                st.caption(step.reasoning)
                if step.decision_allowed is not None:
                    st.caption(f"Scope: {'Authorized' if step.decision_allowed else 'Denied'} · {step.decision_reason or ''}")
                if step.evidence_id:
                    st.caption(f"Evidence ID: `{step.evidence_id}` · Status: {step.tool_status}")
                if step.observations_added:
                    st.caption(f"New services: {step.observations_added}")
                st.markdown("---")

        if agent_result.import_requests:
            st.markdown("### Pending Ingestion Requests")
            st.info("The agent has identified missing tool coverage for the following endpoints:")
            for req in agent_result.import_requests:
                with st.expander(f"Report Needed: {req.tool} — {req.target}:{','.join(str(p) for p in req.ports)}"):
                    st.write(f"**Tool:** {req.tool}")
                    st.write(f"**Target:** {req.target}:{','.join(str(p) for p in req.ports)}")
                    st.write(f"**Reason:** {req.reason}")
                    st.write(f"**Expected Value:** {req.expected_result}")

        st.download_button(
            "Export Agent Trace JSON",
            data=agent_result.model_dump_json(indent=2).encode("utf-8"),
            file_name="proofpath-agent-trace.json",
            mime="application/json",
            key="download_agent_trace",
        )
