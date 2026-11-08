"""ProofPath Streamlit review surface for scans, imports, findings, and plans."""

from __future__ import annotations

import hashlib
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
from proofpath.schemas import Action, ActionName, Finding
from proofpath.scope_guard import ScopeGuard

st.set_page_config(page_title="ProofPath | Security Assessment", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(ellipse at 15% 0%, #182647 0%, #0b1020 42%, #0b1020 100%); }
    .block-container { max-width: 1480px; padding-top: 1.7rem; padding-bottom: 3rem; }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stSidebar"] { background: #10182a; border-right: 1px solid #26334b; }
    [data-testid="stMetric"] { background: linear-gradient(145deg, #172238, #111a2b); border: 1px solid #2b3a53; border-radius: 14px; padding: 0.85rem 1rem; }
    [data-testid="stMetricLabel"] { color: #aab8ce; }
    [data-testid="stMetricValue"] { color: #f3f7ff; }
    div[data-baseweb="tab-list"] { gap: 0.45rem; border-bottom: 1px solid #2a3850; }
    button[data-baseweb="tab"] { border-radius: 10px 10px 0 0; padding: 0.7rem 1rem; }
    div.stButton > button, button[kind="primaryFormSubmit"] { border-radius: 10px; min-height: 2.6rem; font-weight: 650; }
    [data-testid="stExpander"] { border: 1px solid #2b3a53; border-radius: 12px; }
    .pp-hero { border: 1px solid #314563; border-radius: 20px; padding: 1.5rem 1.7rem; margin: 0.3rem 0 1.1rem; background: linear-gradient(115deg, rgba(28,48,77,.96), rgba(16,27,46,.94)); box-shadow: 0 18px 50px rgba(0,0,0,.18); }
    .pp-kicker { color: #77e2c0; font-size: .72rem; font-weight: 750; letter-spacing: .16em; text-transform: uppercase; }
    .pp-hero h1 { color: #f4f7ff; font-size: 2.2rem; line-height: 1.15; margin: .35rem 0 .45rem; }
    .pp-hero p { color: #b7c6dc; font-size: 1rem; margin: 0; max-width: 850px; }
    .pp-pill { display: inline-block; border: 1px solid #347b6a; color: #9cf0d5; background: rgba(22,92,74,.24); border-radius: 999px; padding: .22rem .7rem; font-size: .75rem; font-weight: 700; margin-top: .9rem; }
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
    rows = [
        {
            "title": item.title,
            "asset": item.asset.ip,
            "port": item.port,
            "protocol": item.protocol,
            "severity": item.severity,
            "confidence": item.confidence,
            "status": item.status,
            "sources": ", ".join(item.source_tools),
            "evidence IDs": ", ".join(dict.fromkeys(ref.evidence_id for ref in item.evidence)),
        }
        for item in findings
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)
    for index, finding in enumerate(findings, 1):
        with st.expander(f"Finding {index}: {finding.title} — {finding.asset.ip}:{finding.port}"):
            st.write("Observed facts")
            st.text(finding.observed)
            if finding.inference:
                grounding = verify_finding(finding, LEDGER)
                if grounding.accepted:
                    st.write("AI inference")
                    st.text(finding.inference)
                else:
                    _audit_grounding_rejection(f"finding:{finding.id}:{hash(finding.inference)}", {"finding_id": finding.id, "evidence_ids": [ref.evidence_id for ref in finding.evidence], "violations": list(grounding.violations), "fallback": "AI inference hidden"})
                    st.warning("AI inference rejected by grounding verifier: " + "; ".join(grounding.violations))
            if finding.conflict_notes:
                st.warning("Conflicts: " + " | ".join(finding.conflict_notes))
            for ref in finding.evidence:
                st.markdown(f"**{ref.evidence_id}** · `{ref.locator}`")
                st.code(ref.excerpt or "No excerpt available", language="xml")


with st.sidebar:
    st.subheader("Engagement")
    st.text(f"id: {GUARD.policy.engagement}")
    st.text("allowed: " + ", ".join(GUARD.policy.allowed_cidrs))
    st.text("excluded: " + (", ".join(GUARD.policy.excluded_hosts) or "none"))
    st.text("ports: " + ", ".join(GUARD.policy.allowed_ports))
    st.text("nmap runtime: " + (f"WSL ({NMAP_CONFIG.distribution})" if NMAP_CONFIG.runtime == "wsl" else "native"))
    st.subheader("Integrations")
    st.dataframe([{"tool": row["tool"], "mode": row["mode"]} for row in INTEGRATIONS], hide_index=True)
    try:
        model_config = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
        st.caption("Qwen tag: " + (model_config.model_tag if model_config.model_tag else "not configured"))
        st.caption("Model loads on the first plan request; page startup stays responsive.")
        if st.button("Warm up Qwen now", key="warmup_qwen"):
            try:
                OllamaClient(model_config).warmup()
                AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": model_config.model_tag, "status": "ok"})
                st.session_state.ollama_warmup_status = "Qwen responded successfully."
            except Exception as exc:
                AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": model_config.model_tag, "status": "unavailable", "reason": str(exc)[:500]})
                st.session_state.ollama_warmup_status = "Qwen is unavailable: " + str(exc)[:250]
        if st.session_state.get("ollama_warmup_status"):
            st.caption(st.session_state.ollama_warmup_status)
    except Exception as exc:
        st.caption(f"Ollama config error: {exc}")

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
    <section class="pp-hero">
      <div class="pp-kicker">Authorized assessment workspace</div>
      <h1>ProofPath</h1>
      <p>Evidence-first security assessment. Scope decisions, tool execution, and verification stay deterministic; AI inference remains labeled and reviewable.</p>
      <span class="pp-pill">SCOPE GUARD ACTIVE</span>
    </section>
    """,
    unsafe_allow_html=True,
)
status_cols = st.columns(4)
status_cards = [
    ("Engagement", GUARD.policy.engagement),
    ("Allowed scope", f"{len(GUARD.policy.allowed_cidrs)} CIDR range(s)"),
    ("Nmap runtime", f"WSL · {NMAP_CONFIG.distribution}" if NMAP_CONFIG.runtime == "wsl" else "Native"),
    ("Qwen proposer", "Configured" if model_configured else "Not configured"),
]
for column, (label, value) in zip(status_cols, status_cards):
    column.metric(label, value)
st.caption("Deterministic code decides and verifies. Imported artifacts remain labeled imported. Model availability is checked only when requested.")

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
    ("3. Scans", 3),
    ("4. Ingestion", 4),
    ("5. Analysis", 5),
    ("6. Risk Rank", 6),
    ("7. Human Review", 7),
    ("8. VAPT Report", 8),
]
stepper_html = '<div style="display:flex; justify-content:space-between; margin:0.8rem 0 1.2rem; gap:4px; font-size:0.75rem;">'
for label, num in stages:
    bg = "#1b382b" if num < active_stage else ("#204060" if num == active_stage else "#141c2c")
    border = "#347b6a" if num < active_stage else ("#4a80b0" if num == active_stage else "#253347")
    color = "#9cf0d5" if num < active_stage else ("#ffffff" if num == active_stage else "#78879e")
    icon = "&#10003; " if num < active_stage else ("&#9654; " if num == active_stage else "")
    stepper_html += f'<div style="flex:1; text-align:center; padding:0.4rem 0.2rem; background:{bg}; border:1px solid {border}; border-radius:6px; color:{color}; font-weight:600;">{icon}{label}</div>'
stepper_html += '</div>'
st.markdown(stepper_html, unsafe_allow_html=True)

tabs = st.tabs(["Assess", "Findings", "Plan", "Imports", "Risk", "Approvals", "Report", "Assistant", "Agent"])

with tabs[0]:
    st.subheader("Assess a target")
    with st.form("assess"):
        request = st.text_input("Request", placeholder="List services on the lab host")
        target = st.text_input("Target", placeholder="10.10.1.5")
        ports_text = st.text_input("Ports", value="80,443")
        skip_host_discovery = st.checkbox("Skip nmap host discovery (-Pn)", value=False)
        source_mode = st.radio("Nmap source", ["Live scan", "Import recorded nmap XML"], horizontal=True)
        uploaded_xml = st.file_uploader("Recorded nmap XML (import only)", type=["xml"]) if source_mode.startswith("Import") else None
        submitted = st.form_submit_button("Check scope and continue")

    if submitted:
        request_text = request.strip()
        target_text = target.strip()
        if not request_text or not target_text:
            st.error("A request and target are both required.")
        else:
            AUDIT.append("analyst_request", "analyst", {"request": request_text[:500], "target": target_text, "ports": ports_text})
            try:
                ports = _ports(ports_text)
                if source_mode.startswith("Import") and uploaded_xml is None:
                    raise ValueError("Choose a recorded nmap XML file to import.")
                if source_mode.startswith("Import") and len(uploaded_xml.getvalue()) > MAX_IMPORT_BYTES:
                    raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
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
                st.write(f"Scope allowed: **{result.decision.allowed}**")
                st.write(f"Reason: {result.decision.reason}")
                st.write(f"Status: `{result.status}` · source mode: **{source_label}**")
                st.write(f"Evidence ID: `{result.evidence_id or 'none'}`")
                st.caption(result.message)
                if source_label == "imported":
                    st.info(
                        f"Tool: nmap · filename: {uploaded_xml.name} · SHA-256: {result.sha256 or 'unavailable'} · "
                        f"source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · "
                        f"parse errors: {1 if result.status == 'error' else 0}"
                    )
                elif result.status in {"tool_not_found", "timeout", "error", "denied"}:
                    st.warning(result.message)
                if result.services:
                    st.session_state.observations.extend(result.services)
                    st.dataframe([row.model_dump() for row in result.services], hide_index=True, use_container_width=True)
                else:
                    st.info("Observed ports: none")
            except ValueError as exc:
                st.error(str(exc))

    with st.expander("Recent assessment messages"):
        for item in st.session_state.transcript:
            st.text(item)

with tabs[1]:
    st.subheader("Findings")
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
        for item in analyze_findings(merged_findings, st.session_state.observations, GUARD.policy.engagement):
            st.markdown(f"**Skeptic hypothesis** · {item.hypothesis.id}: {item.hypothesis.statement}")
            st.caption("Evidence for: " + (", ".join(ref.evidence_id for ref in item.hypothesis.evidence_for) or "none") + " · Evidence against: " + (", ".join(ref.evidence_id for ref in item.hypothesis.evidence_against) or "none"))
            st.caption(item.planner_reason)
            if st.button("Gate one-port skeptic recheck", key="skeptic_" + item.hypothesis.id):
                try:
                    result = gate_recheck_proposal(item, GUARD, AUDIT, LEDGER)
                    st.write("Recheck proposal: " + result.status + " · " + result.message)
                except Exception as exc:
                    st.error("Could not gate skeptic proposal: " + str(exc))
    else:
        st.info("No imported vulnerability findings yet. Nmap service banners alone do not create findings.")

with tabs[2]:
    st.subheader("Plan")
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
    for skipped, reason in skipped_candidates:
        st.caption(f"Skipped duplicate {skipped.action.target}:{','.join(str(port) for port in skipped.action.ports)} — {reason}")
    if not candidates:
        st.info("No unexecuted open web service candidates are available.")
    else:
        for candidate in candidates:
            st.markdown(
                f"**{candidate.candidate_id} · {candidate.action.name.value} · "
                f"{candidate.action.target}:{','.join(str(port) for port in candidate.action.ports)}**"
            )
            st.write(candidate.planner_reason)
            st.caption(
                f"Exposure: {candidate.exposure_state} · Evidence: "
                f"{', '.join(candidate.observed_evidence_ids)} · Risk score: "
                f"{candidate.risk_score if candidate.risk_score is not None else 'not scored'}"
            )
            st.caption("Expected result: " + candidate.expected_result)
        if st.button("Generate plan", key="generate_plan"):
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
                if used_fallback:
                    st.warning("Proposer unavailable: rule-based plan shown")
            except Exception as exc:
                AUDIT.append("proposer_unavailable", "model-proposer", {"reason": str(exc)[:500]})
                try:
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
                    st.caption(str(exc))
                except Exception as fallback_exc:
                    st.warning("Proposer unavailable and fallback could not be queued: " + str(fallback_exc)[:300])

    proposal = st.session_state.plan_proposal
    if proposal is not None:
        selected_candidate = st.session_state.get("plan_candidate_context") or next(
            (item for item in candidates if item.action == proposal.action),
            None,
        )
        st.caption(f"Selected candidate: {proposal.candidate_id}")
        st.markdown(f"**Proposed action:** `{proposal.action.name.value}` · {proposal.action.target} · ports {proposal.action.ports}")
        matching_observations = [row for row in st.session_state.observations if row.ip == proposal.action.target and row.port in proposal.action.ports and row.state.casefold() == "open"]
        live_rows = [row for row in matching_observations if row.source_mode == "live"]
        imported_rows = [row for row in matching_observations if row.source_mode == "imported"]
        exposure = "live-observed" if live_rows else "imported" if imported_rows else "unknown"
        exposure_ids = [row.evidence_id for row in (live_rows or imported_rows)]
        st.markdown("**Decision trace (code generated)**")
        if selected_candidate is not None:
            trace_exposure = selected_candidate.exposure_state
            trace_evidence = selected_candidate.observed_evidence_ids
            st.write(
                f"Trigger: {selected_candidate.planner_reason} · exposure: {trace_exposure} · "
                f"evidence: {', '.join(trace_evidence) or 'none'}"
            )
            st.write("Expected result: " + selected_candidate.expected_result)
        else:
            trace_exposure = exposure
            trace_evidence = list(dict.fromkeys(exposure_ids))
            st.write(f"Trigger: scoped web observation · exposure: {trace_exposure} · evidence: {', '.join(trace_evidence) or 'none'}")
        if proposal.action.name == ActionName.NMAP_SCAN:
            st.write("Next operation: a one-port Nmap TCP connect recheck. Approval queues the action; the separate Run button below starts it through the scope guard.")
        elif proposal.action.name == ActionName.IMPORT_BURP:
            st.write("Next operation: import a matching Burp XML export for this endpoint. This action does not start a Burp scan.")
            st.write("Expected result: tool-reported web issues enter the finding normalizer and correlation workflow with their source evidence references.")
        elif proposal.action.name == ActionName.IMPORT_NESSUS:
            st.write("Next operation: import a Nessus .nessus XML export for this host. This action does not start a Nessus scan.")
            st.write("Expected result: tool-reported infrastructure issues enter the finding normalizer and correlation workflow with their source evidence references.")
        elif proposal.action.name == ActionName.IMPORT_NIKTO:
            st.write("Next operation: import a Nikto JSON/XML report for this web endpoint. This action does not start a Nikto scan.")
            st.write("Expected result: tool-reported web server misconfigurations enter normalizer and correlation.")
        elif proposal.action.name == ActionName.IMPORT_ZAP:
            st.write("Next operation: import an OWASP ZAP report for this endpoint. This action does not start a live ZAP scan.")
            st.write("Expected result: automated web application and API alert findings enter normalizer and correlation.")
        elif proposal.action.name == ActionName.IMPORT_OPENVAS:
            st.write("Next operation: import an OpenVAS / Greenbone XML report for this host. This action does not start an OpenVAS scan.")
            st.write("Expected result: infrastructure vulnerability findings enter normalizer and correlation.")
        elif proposal.action.name == ActionName.IMPORT_METASPLOIT:
            st.write("Next operation: import a human-approved Metasploit verification report. Autonomous exploitation is strictly prohibited.")
            st.write("Expected result: verified exploitability findings enter normalizer with full audit traceability.")
        else:
            st.write(f"Next operation: review the typed action and its scope decision before proceeding.")
        st.markdown("**Observed facts (code generated)**")
        risk_score = selected_candidate.risk_score if selected_candidate is not None else None
        risk_factors = selected_candidate.risk_factors if selected_candidate is not None else []
        st.write(f"Exposure: {trace_exposure} · Evidence IDs: {', '.join(trace_evidence) or 'none'}")
        st.write(f"Risk score: {risk_score if risk_score is not None else 'not scored'}")
        if risk_factors:
            st.caption("Why this score: " + "; ".join(risk_factors))
        else:
            st.caption("Why: no matching vulnerability finding is available for a numeric risk score.")
        model_claims = " ".join([proposal.rationale.inferred, proposal.rationale.why, *proposal.rationale.observed])
        cited_ids = list(dict.fromkeys(re.findall(r"\bEV-\d+\b", model_claims)))
        grounding = verify_text(model_claims, cited_ids, LEDGER)
        if grounding.accepted:
            st.markdown("**AI inference**")
            st.write("Observed claims: " + " ".join(proposal.rationale.observed))
            st.write("Inference: " + proposal.rationale.inferred)
            st.write("Why: " + proposal.rationale.why)
        else:
            _audit_grounding_rejection(f"action:{proposal.action.id}:{hash(model_claims)}", {"action_id": proposal.action.id, "evidence_ids": cited_ids, "violations": list(grounding.violations), "fallback": "rule plan only; model inference hidden"})
            st.warning("Model rationale rejected by grounding verifier: " + "; ".join(grounding.violations))
        st.write("Gate status: " + ("rule fallback" if st.session_state.plan_fallback else st.session_state.plan_status))
        for call_number, metrics in enumerate(st.session_state.plan_metrics, 1):
            rate = f"{metrics['tokens_per_second']} tokens/s" if metrics.get("tokens_per_second") is not None else "generation rate unavailable"
            st.caption(f"Ollama call {call_number}: load {metrics['load_ms']} ms · prompt {metrics['prompt_ms']} ms/{metrics['prompt_tokens']} tokens · generation {metrics['generation_ms']} ms/{metrics['output_tokens']} tokens ({rate}) · total {metrics['total_ms']} ms")
        if st.session_state.plan_status == "planned":
            left, right = st.columns(2)
            if left.button("Approve plan", key="approve_plan"):
                checked = execute_action(
                    proposal.action,
                    GUARD,
                    AUDIT,
                    LEDGER,
                    {proposal.action.name: ProposalGateAdapter(candidate_match=True, proposal=proposal)},
                )
                if checked.decision.allowed:
                    follow_up = {
                        ActionName.NMAP_SCAN: "Approved for a separate one-port Nmap TCP connect recheck.",
                        ActionName.IMPORT_BURP: "Approved for analyst follow-up; a Burp XML export must still be supplied in Imports.",
                        ActionName.IMPORT_NESSUS: "Approved for analyst follow-up; a Nessus XML export must still be supplied in Imports.",
                        ActionName.IMPORT_NIKTO: "Approved for analyst follow-up; a Nikto report must still be supplied in Imports.",
                        ActionName.IMPORT_ZAP: "Approved for analyst follow-up; an OWASP ZAP report must still be supplied in Imports.",
                        ActionName.IMPORT_OPENVAS: "Approved for analyst follow-up; an OpenVAS XML report must still be supplied in Imports.",
                        ActionName.IMPORT_METASPLOIT: "Approved for analyst follow-up; a Metasploit report must still be supplied in Imports.",
                    }.get(proposal.action.name, "Approved for analyst follow-up.")
                    AUDIT.append("plan_approved", "analyst", {"action_id": proposal.action.id, "note": follow_up})
                    st.session_state.plan_status = "approved"
                    st.success(follow_up)
                else:
                    st.error("Plan failed the current scope check: " + checked.message)
            if right.button("Skip plan", key="skip_plan"):
                AUDIT.append("plan_skipped", "analyst", {"action_id": proposal.action.id})
                st.session_state.plan_status = "skipped"
                st.info("Plan skipped.")
        if st.session_state.plan_status == "approved" and proposal.action.name == ActionName.NMAP_SCAN:
            run_key = "plan_scan_attempted_" + proposal.action.id
            if run_key in st.session_state:
                st.info(st.session_state[run_key])
            elif st.button("Run one-port Nmap TCP connect recheck", key="run_plan_nmap"):
                analyst_action = proposal.action.model_copy(update={"requested_by": "analyst"})
                result = execute_action(analyst_action, GUARD, AUDIT, LEDGER, NMAP_ADAPTERS)
                if result.services:
                    st.session_state.observations.extend(result.services)
                message = (
                    f"Nmap recheck status: {result.status} · evidence: {result.evidence_id or 'none'} · "
                    f"scope allowed: {result.decision.allowed} · {result.message}"
                )
                st.session_state[run_key] = message
                st.write(message)

with tabs[3]:
    st.subheader("Imports — raw files are labeled imported")
    left, right = st.columns(2)
    with left:
        nessus_file = st.file_uploader("Nessus .nessus XML", type=["nessus", "xml"], key="nessus_import_file")
        if st.button("Import Nessus", key="import_nessus"):
            if nessus_file is None:
                st.error("Choose a .nessus file.")
            else:
                try:
                    raw = nessus_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_nessus_xml(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: Nessus · filename: {nessus_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "nessus", "filename": nessus_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Nessus", nessus_file.name, raw, exc))
    with right:
        burp_file = st.file_uploader("Burp issue XML (DTD-free)", type=["xml"], key="burp_import_file")
        if st.button("Import Burp", key="import_burp"):
            if burp_file is None:
                st.error("Choose a DTD-free Burp XML export.")
            else:
                try:
                    raw = burp_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_burp_xml(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: Burp · filename: {burp_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_issues} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "burp", "filename": burp_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Burp", burp_file.name, raw, exc))
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "burp", "filename": burp_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Burp", burp_file.name, raw, exc))

    if st.session_state.raw_findings:
        st.caption(f"{len(st.session_state.raw_findings)} imported raw finding record(s); merged view is in Findings.")

    st.markdown("---")
    st.markdown("**Additional Tool Adapters (All 7 Problem Statement Tools)**")
    left2, right2 = st.columns(2)
    with left2:
        openvas_file = st.file_uploader("OpenVAS / Greenbone XML report", type=["xml"], key="openvas_import_file")
        if st.button("Import OpenVAS", key="import_openvas"):
            if openvas_file is None:
                st.error("Choose an OpenVAS XML report file.")
            else:
                try:
                    raw = openvas_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_openvas_xml(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: OpenVAS · filename: {openvas_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "openvas", "filename": openvas_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("OpenVAS", openvas_file.name, raw, exc))
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "openvas", "filename": openvas_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("OpenVAS", openvas_file.name, raw, exc))
    with right2:
        nikto_file = st.file_uploader("Nikto report (JSON or XML)", type=["json", "xml"], key="nikto_import_file")
        if st.button("Import Nikto", key="import_nikto"):
            if nikto_file is None:
                st.error("Choose a Nikto JSON or XML report.")
            else:
                try:
                    raw = nikto_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_nikto_report(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: Nikto · filename: {nikto_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "nikto", "filename": nikto_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Nikto", nikto_file.name, raw, exc))
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "nikto", "filename": nikto_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Nikto", nikto_file.name, raw, exc))

    left3, right3 = st.columns(2)
    with left3:
        zap_file = st.file_uploader("OWASP ZAP report (XML or JSON)", type=["xml", "json"], key="zap_import_file")
        if st.button("Import OWASP ZAP", key="import_zap"):
            if zap_file is None:
                st.error("Choose an OWASP ZAP report.")
            else:
                try:
                    raw = zap_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_zap_report(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: OWASP ZAP · filename: {zap_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "zap", "filename": zap_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("OWASP ZAP", zap_file.name, raw, exc))
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "zap", "filename": zap_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("OWASP ZAP", zap_file.name, raw, exc))
    with right3:
        metasploit_file = st.file_uploader("Metasploit export (XML or JSON)", type=["xml", "json"], key="metasploit_import_file")
        if st.button("Import Metasploit", key="import_metasploit"):
            if metasploit_file is None:
                st.error("Choose a Metasploit report.")
            else:
                try:
                    raw = metasploit_file.getvalue()
                    if len(raw) > MAX_IMPORT_BYTES:
                        raise ValueError(f"upload exceeds the {MAX_IMPORT_BYTES}-byte limit")
                    result = import_metasploit_report(raw, GUARD, AUDIT, LEDGER)
                    _append_findings(result.findings)
                    st.success(f"Tool: Metasploit · filename: {metasploit_file.name} · SHA-256: {result.sha256} · evidence ID: {result.evidence_id} · source_mode=imported · parsed: {result.parsed_items} · dropped out of scope: {result.dropped_items} · parse errors: 0")
                except ValueError as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "metasploit", "filename": metasploit_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Metasploit", metasploit_file.name, raw, exc))
                except Exception as exc:
                    AUDIT.append("import_parse_error", "analyst", {"tool": "metasploit", "filename": metasploit_file.name, "source_mode": "imported", "error": str(exc)[:500]})
                    st.error(_import_failure("Metasploit", metasploit_file.name, raw, exc))

with tabs[4]:
    st.subheader("Risk prioritization")
    if st.button("Reload verified public CVE context", key="reload_public_intel"):
        try:
            st.session_state.public_threat_intel = load_public_threat_intel(DATA_ROOT / "threat_intel" / "training", LEDGER)
            st.session_state.public_threat_intel_error = ""
        except Exception as exc:
            st.session_state.public_threat_intel = None
            st.session_state.public_threat_intel_error = str(exc)[:300]
    public_intel = st.session_state.public_threat_intel
    if public_intel:
        st.caption(
            f"Public context from CISA KEV {public_intel.kev_evidence_id} and FIRST EPSS "
            f"{public_intel.epss_evidence_id} · captured {public_intel.fetched_at}. "
            "KEV absence is not treated as proof of no exploitation; NVD CVSS remains separate from scanner CVSS."
        )
    elif st.session_state.public_threat_intel_error:
        st.warning("Public context cache failed verification: " + st.session_state.public_threat_intel_error)
    else:
        st.info("No verified public CVE context is cached. Run `python -B scripts/train_public_risk_model.py` to fetch and ledger the current feeds.")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    assets = sorted({item.asset.ip for item in findings})
    for asset in assets:
        previous = st.session_state.criticality_by_asset.get(asset, "medium")
        selected = st.selectbox("Asset criticality · " + asset, ["low", "medium", "high"], index=["low", "medium", "high"].index(previous), key="criticality_" + asset)
        if selected != previous:
            st.session_state.criticality_by_asset[asset] = selected
            AUDIT.append("asset_criticality_changed", "analyst", {"asset": asset, "old": previous, "new": selected})
    ranked = rank_findings(findings, st.session_state.observations, st.session_state.criticality_by_asset, public_intel)
    if ranked:
        st.caption(f"Risk table rendered · {len(ranked)} ranked finding(s)")
        rows = []
        for item in ranked:
            factor_text = "; ".join(f"{factor.name}={factor.value} (source: {factor.source}; weight: {factor.weight:.0%}; {'included' if factor.included else 'excluded'})" for factor in item.factors)
            rows.append({"rank": item.rank, "finding": item.finding.id, "asset": item.finding.asset.ip, "severity": item.finding.severity, "CVSS": item.finding.cvss if item.finding.cvss is not None else "not provided", "status": item.status_label, "priority score": item.priority_score if item.priority_score is not None else "not scored", "factors": factor_text})
        st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        st.info("Import findings to calculate risk priority.")

with tabs[5]:
    st.subheader("Human approvals")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    web_findings = [item for item in findings if item.port in {80, 443, 8080, 8443} or (item.service or "").casefold() in {"http", "https"}]
    if web_findings:
        selected_finding = st.selectbox("Finding to validate", web_findings, format_func=lambda item: f"{item.id} · {item.asset.ip}:{item.port} · {item.title}", key="approval_finding")
        with st.form("approval_request_form"):
            requester = st.text_input("Requester identity", value="analyst")
            method = st.selectbox("Method", ["GET", "HEAD"])
            path_options = GUARD.policy.allowed_validation_paths or ["/"]
            path = st.selectbox("Allowlisted path", path_options)
            justification = st.text_input("Reason for this non-destructive check")
            request_submitted = st.form_submit_button("Request approval")
        if request_submitted:
            try:
                if not requester.strip():
                    raise ValueError("requester identity is required")
                action = Action(id=uuid.uuid4().hex, name=ActionName.ACTIVE_VALIDATE, target=selected_finding.asset.ip, ports=[selected_finding.port], arguments={"method": method, "path": path, "finding_id": selected_finding.id}, engagement_id=GUARD.policy.engagement, requested_by=requester.strip())
                scope_result = execute_action(action, GUARD, AUDIT, LEDGER, {})
                if "approval" not in scope_result.message:
                    st.error("Request denied by scope policy: " + scope_result.message)
                else:
                    approval = request_approval(action, requester.strip(), justification)
                    st.session_state.approval_records[approval.id] = {"request": approval, "action": action}
                    AUDIT.append("approval_requested", requester.strip(), {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "action": action.model_dump(mode="json"), "justification": approval.justification, "expires_at": approval.expires_at.isoformat()})
                    st.success("Approval request recorded. A different named person must decide it.")
            except Exception as exc:
                st.error("Could not create approval request: " + str(exc))
    else:
        st.info("Import a web finding before requesting active validation.")

    approver = st.text_input("Approver identity", key="approval_approver")
    for approval_id, record in list(st.session_state.approval_records.items()):
        approval = record["request"]
        action = record["action"]
        st.write(f"{approval.state.value}: {action.arguments['method']} {action.target}:{action.ports[0]}{action.arguments['path']} · finding {action.arguments['finding_id']} · requested by {approval.requested_by} · expires {approval.expires_at.isoformat()}")
        if approval.state.value == "pending":
            approve_col, deny_col = st.columns(2)
            for button, approved in ((approve_col, True), (deny_col, False)):
                label = "Approve" if approved else "Deny"
                if button.button(label, key=f"{label}_{approval_id}"):
                    try:
                        decided = decide_approval(approval, approver, approved=approved)
                        record["request"] = decided
                        AUDIT.append("approval_decision", approver, {"approval_id": approval.id, "action_id": action.id, "action_hash": approval.action_hash, "requested_by": approval.requested_by, "decided_by": approver, "state": decided.state.value, "decided_at": decided.decided_at.isoformat() if decided.decided_at else None})
                        if not approved and decided.state.value == "denied":
                            st.session_state.raw_findings = [item.model_copy(update={"validation_status": "rejected_by_human"}) if item.id == action.arguments["finding_id"] else item for item in st.session_state.raw_findings]
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
        elif approval.state.value == "approved" and approval.used_at is None:
            if st.button("Run approved request once", key="run_" + approval_id):
                try:
                    result = execute_action(action, GUARD, AUDIT, LEDGER, {ActionName.ACTIVE_VALIDATE: ActiveValidationAdapter(action, approval)}, approval=approval)
                    record["request"] = approval.model_copy(update={"used_at": datetime.now(timezone.utc)})
                    outcome = next((entry for entry in reversed(AUDIT.read_entries()) if entry.event_type == "active_validation_outcome" and entry.details.get("approval_id") == approval_id), None)
                    if outcome and outcome.details.get("validation_status") == "validated_approved":
                        st.session_state.raw_findings = [item.model_copy(update={"validation_status": "validated_approved"}) if item.id == action.arguments["finding_id"] else item for item in st.session_state.raw_findings]
                    st.write(result.message)
                    st.rerun()
                except Exception as exc:
                    st.error("Approved request failed safely: " + str(exc))
    if st.session_state.approval_records:
        st.caption("Approval history is stored in the hash-chained audit log.")

with tabs[6]:
    st.subheader("Assessment report")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    if st.button("Generate PDF report", disabled=not findings):
        try:
            report_dir = DATA_ROOT / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_result = generate_pdf(findings, st.session_state.observations, LEDGER, AUDIT, report_dir / "assessment.pdf", engagement=GUARD.policy.engagement, scope_cidrs=GUARD.policy.allowed_cidrs, criticality=st.session_state.criticality_by_asset, public_intel=st.session_state.public_threat_intel)
            st.session_state.report_path = report_result["path"]
            st.session_state.report_hash = report_result["sha256"]
            st.session_state.sarif_path = report_result.get("sarif_path", "")
            st.session_state.report_status = f"Grounded findings: {report_result['grounded_findings']}/{report_result['total_findings']}"
        except Exception as exc:
            AUDIT.append("report_generation_failed", "analyst", {"reason": f"{type(exc).__name__}: {exc}"[:500]})
            st.error("Could not generate PDF report: " + str(exc))
    if st.session_state.report_path and Path(st.session_state.report_path).is_file():
        st.caption("SHA-256: " + st.session_state.report_hash)
        st.caption(st.session_state.report_status)
        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button("Download PDF report", data=Path(st.session_state.report_path).read_bytes(), file_name="proofpath-assessment.pdf", mime="application/pdf")
        with dl_col2:
            sarif_file = Path(st.session_state.get("sarif_path", ""))
            if sarif_file.is_file():
                st.download_button("Download OASIS SARIF v2.1.0", data=sarif_file.read_bytes(), file_name="proofpath-assessment.sarif", mime="application/json")

    st.markdown("---")
    with st.expander("Retesting & change comparison (baseline vs. current)"):
        st.caption("Compare findings against a prior assessment run or baseline export to track remediation progress.")
        baseline_file = st.file_uploader("Upload prior findings JSON (current-findings.json)", type=["json"], key="baseline_findings_file")
        if baseline_file is not None:
            try:
                raw_baseline = json.loads(baseline_file.getvalue().decode("utf-8"))
                baseline_findings = [Finding.model_validate(item) for item in raw_baseline]
                diff = compare_assessments(baseline_findings, findings)
                d_col1, d_col2, d_col3 = st.columns(3)
                d_col1.metric("New Findings", diff.total_new)
                d_col2.metric("Persisting Findings", diff.total_persisting)
                d_col3.metric("Remediated / Closed", diff.total_remediated)
                if diff.new_findings:
                    st.write("**Newly identified findings:**")
                    st.dataframe([{"id": f.id, "title": f.title, "asset": f.asset.ip, "port": f.port, "severity": f.severity} for f in diff.new_findings], hide_index=True)
                if diff.remediated_findings:
                    st.write("**Verified remediated / refuted findings:**")
                    st.dataframe([{"id": f.id, "title": f.title, "asset": f.asset.ip, "port": f.port, "status": f.status} for f in diff.remediated_findings], hide_index=True)
                st.download_button("Download change comparison delta JSON", data=json.dumps(diff.to_dict(), indent=2).encode("utf-8"), file_name="proofpath-change-diff.json", mime="application/json")
            except Exception as exc:
                st.error("Could not parse baseline findings: " + str(exc))

with tabs[7]:
    st.subheader("Conversational Security Assistant")
    st.caption("AI-powered conversational security guide following the 8-stage VAPT lifecycle. Evaluates scope boundaries, recommends tools, and explains security reasoning.")
    query = st.text_input("Ask the Security Assistant", placeholder="e.g. Assess 10.10.1.5 for web vulnerabilities, or check if 10.20.0.10 is in scope", key="conv_assistant_query")
    if st.button("Ask Assistant", key="btn_ask_assistant"):
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
                st.error(f"Scope Alert: Target {reply.target} is denied by scope policy: {reply.scope_reason}")
        else:
            st.warning("Please enter a question or assessment request.")

    if st.session_state.transcript:
        with st.expander("Full Conversation Transcript"):
            for line in st.session_state.transcript:
                st.text(line)

with tabs[8]:
    st.subheader("Autonomous VAPT Agent")
    st.caption(
        "ReAct-style agentic orchestrator that autonomously plans, executes, and reflects on "
        "assessment steps. Every tool invocation passes through the Scope Guard choke point. "
        "Import-only tools pause for analyst-supplied reports."
    )

    # Agent configuration
    with st.expander("Agent Configuration", expanded=not st.session_state.agent_result):
        agent_col1, agent_col2 = st.columns(2)
        with agent_col1:
            max_steps = st.slider("Maximum agent steps", min_value=1, max_value=50, value=15, key="agent_max_steps")
            auto_nmap = st.checkbox("Auto-execute Nmap scans", value=False, key="agent_auto_nmap",
                                    help="When enabled, the agent will automatically run live Nmap scans through WSL. Disable to treat Nmap as import-only.")
        with agent_col2:
            pause_imports = st.checkbox("Pause for import requests", value=True, key="agent_pause_imports",
                                        help="When enabled, import-only tools request analyst files instead of being skipped.")

    # Run agent button
    if st.button("🤖 Start Autonomous Assessment", key="btn_run_agent", type="primary"):
        with st.spinner("Agent is running the ReAct assessment loop..."):
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

                agent = VAPTAgent(
                    GUARD, AUDIT, LEDGER, NMAP_ADAPTERS, agent_config,
                )

                # Load current session state into agent
                agent.load_state(
                    observations=st.session_state.observations,
                    findings=st.session_state.raw_findings,
                )

                result = agent.run()
                st.session_state.agent_result = result

                # Sync agent state back to session
                st.session_state.observations = agent.observations
                st.session_state.raw_findings = agent.raw_findings

                st.success(f"Agent completed with status: **{result.status}** · {len(result.steps)} steps · {result.duration_seconds:.1f}s")
            except Exception as exc:
                st.error(f"Agent error: {exc}")

    # Display agent results
    agent_result = st.session_state.agent_result
    if agent_result is not None:
        # Summary metrics
        st.markdown("---")
        st.markdown("### Agent Run Summary")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Status", agent_result.status.replace("_", " ").title())
        m2.metric("Steps Taken", len(agent_result.steps))
        m3.metric("Observations", agent_result.total_observations)
        m4.metric("Findings", agent_result.total_findings)

        m5, m6, m7, m8 = st.columns(4)
        m5.metric("Candidates Evaluated", agent_result.total_candidates_evaluated)
        m6.metric("Import Requests", len(agent_result.import_requests))
        m7.metric("Duration", f"{agent_result.duration_seconds:.1f}s")
        m8.metric("Run ID", agent_result.run_id[:8])

        # Assessment plan
        if agent_result.plan:
            with st.expander("📋 Assessment Plan", expanded=True):
                st.write(agent_result.plan.reasoning)
                if agent_result.plan.targets:
                    st.caption("Targets: " + ", ".join(agent_result.plan.targets))
                if agent_result.plan.planned_actions:
                    st.caption("Planned actions: " + ", ".join(agent_result.plan.planned_actions))

        # Step-by-step execution trace
        with st.expander("🔄 ReAct Execution Trace", expanded=True):
            for step in agent_result.steps:
                icon = {
                    StepType.OBSERVE: "🔍",
                    StepType.THINK: "🧠",
                    StepType.ACT: "⚡",
                    StepType.REFLECT: "💭",
                    StepType.IMPORT_REQUEST: "📥",
                    StepType.COMPLETE: "✅",
                    StepType.ERROR: "❌",
                }.get(step.step_type, "•")

                step_label = f"{icon} Step {step.step_number} — **{step.step_type.value.upper()}**"
                if step.action_name:
                    step_label += f" · `{step.action_name}`"
                if step.target:
                    step_label += f" · {step.target}"
                if step.ports:
                    step_label += f":{','.join(str(p) for p in step.ports)}"

                st.markdown(step_label)
                st.caption(step.reasoning)

                if step.decision_allowed is not None:
                    scope_status = "✅ Allowed" if step.decision_allowed else "❌ Denied"
                    st.caption(f"Scope: {scope_status} · {step.decision_reason or ''}")
                if step.evidence_id:
                    st.caption(f"Evidence: `{step.evidence_id}` · Status: {step.tool_status}")
                if step.observations_added:
                    st.caption(f"New observations: {step.observations_added}")
                if step.duration_ms > 0:
                    st.caption(f"Duration: {step.duration_ms:.0f} ms")

                st.markdown("---")

        # Pending import requests
        if agent_result.import_requests:
            st.markdown("### 📥 Pending Import Requests")
            st.info("The agent needs the following tool reports to continue the assessment. Supply them in the **Imports** tab.")
            for req in agent_result.import_requests:
                with st.expander(f"📄 {req.tool} — {req.target}:{','.join(str(p) for p in req.ports)}"):
                    st.write(f"**Tool:** {req.tool}")
                    st.write(f"**Target:** {req.target}:{','.join(str(p) for p in req.ports)}")
                    st.write(f"**Reason:** {req.reason}")
                    st.write(f"**Expected Result:** {req.expected_result}")
                    st.caption(f"Candidate ID: {req.candidate_id} · Action: {req.action_name}")

        # Download agent trace
        st.download_button(
            "📥 Download Agent Trace JSON",
            data=agent_result.model_dump_json(indent=2).encode("utf-8"),
            file_name="proofpath-agent-trace.json",
            mime="application/json",
            key="download_agent_trace",
        )
