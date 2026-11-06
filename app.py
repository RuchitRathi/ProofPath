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
from proofpath.xml_evidence import MAX_IMPORT_BYTES
from proofpath.schemas import Action, ActionName, Finding
from proofpath.scope_guard import ScopeGuard

st.set_page_config(page_title="ProofPath", layout="wide")
st.title("ProofPath")
st.caption("Deterministic code decides and verifies. Imported artifacts remain labeled imported.")

GUARD = ScopeGuard.from_yaml(SCOPE_CONFIG_PATH)
AUDIT = AuditLog(DATA_ROOT / "audit.jsonl")
LEDGER = Ledger(DATA_ROOT / "evidence")
NMAP_CONFIG = NmapExecutionConfig.from_yaml(ROOT / "nmap.yaml")
NMAP_ADAPTERS = {
    ActionName.NMAP_SCAN: NmapAdapter(
        wsl_distribution=NMAP_CONFIG.distribution if NMAP_CONFIG.runtime == "wsl" else None
    )
}

if not st.session_state.get("ollama_warmup_attempted", False):
    st.session_state.ollama_warmup_attempted = True
    try:
        warmup_config = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
        if warmup_config.model_tag.strip():
            OllamaClient(warmup_config).warmup()
            AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": warmup_config.model_tag, "status": "ok"})
        else:
            AUDIT.append("ollama_warmup", "model-proposer", {"model_tag": "", "status": "skipped_blank_tag"})
    except Exception as exc:
        AUDIT.append("ollama_warmup", "model-proposer", {"status": "unavailable", "reason": str(exc)[:500]})


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
        st.caption("Ollama: configured" if model_config.model_tag else "Ollama: model tag not configured")
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
if "criticality_by_asset" not in st.session_state:
    st.session_state.criticality_by_asset = {}
if "approval_records" not in st.session_state:
    st.session_state.approval_records = {}
if "report_path" not in st.session_state:
    st.session_state.report_path = ""

tabs = st.tabs(["Assess", "Findings", "Plan", "Imports", "Risk", "Approvals", "Report"])

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
    candidates, skipped_candidates = RulePlanner().evaluate(st.session_state.observations, GUARD.policy.engagement, executed=executed)
    for skipped, reason in skipped_candidates:
        st.caption(f"Skipped duplicate {skipped.action.target}:{','.join(str(port) for port in skipped.action.ports)} — {reason}")
    if not candidates:
        st.info("No unexecuted open web service candidates are available.")
    else:
        for candidate in candidates:
            st.write(f"{candidate.action.target}:{candidate.action.ports[0]} — {candidate.planner_reason}")
            st.caption("Observed evidence: " + ", ".join(candidate.observed_evidence_ids))
        if st.button("Generate plan", key="generate_plan"):
            try:
                configured = OllamaConfig.from_yaml(OLLAMA_CONFIG_PATH)
                client = OllamaClient(configured)
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
                st.session_state.plan_status = result.status if result else ""
                st.session_state.plan_candidate_count = len(candidates)
                st.session_state.plan_fallback = used_fallback
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
                    st.session_state.plan_status = result.status if result else ""
                    st.session_state.plan_candidate_count = len(candidates)
                    st.session_state.plan_fallback = used_fallback
                    st.warning("Proposer unavailable: deterministic top rule-ranked candidate shown")
                    st.caption(str(exc))
                except Exception as fallback_exc:
                    st.warning("Proposer unavailable and fallback could not be queued: " + str(fallback_exc)[:300])

    proposal = st.session_state.plan_proposal
    if proposal is not None:
        st.caption(f"Selected candidate: {proposal.candidate_id}")
        st.markdown(f"**Proposed action:** `{proposal.action.name.value}` · {proposal.action.target} · ports {proposal.action.ports}")
        matching_observations = [row for row in st.session_state.observations if row.ip == proposal.action.target and row.port in proposal.action.ports and row.state.casefold() == "open"]
        live_rows = [row for row in matching_observations if row.source_mode == "live"]
        imported_rows = [row for row in matching_observations if row.source_mode == "imported"]
        exposure = "live-observed" if live_rows else "imported" if imported_rows else "unknown"
        exposure_ids = [row.evidence_id for row in (live_rows or imported_rows)]
        st.markdown("**Decision trace (code generated)**")
        if proposal.action.name == ActionName.IMPORT_BURP:
            st.write(f"Trigger: open web service at {proposal.action.target}:{proposal.action.ports[0]} · source: {exposure} · evidence: {', '.join(dict.fromkeys(exposure_ids)) or 'none'}")
            st.write("Next operation: import a matching Burp XML export for this endpoint. This action does not start a Burp scan.")
            st.write("Expected result: tool-reported web issues enter the finding normalizer and correlation workflow with their source evidence references.")
        else:
            st.write(f"Trigger: candidate {proposal.candidate_id} was generated by the rule planner for {proposal.action.target}:{','.join(str(port) for port in proposal.action.ports)}.")
            st.write("Next operation: review the typed action and its scope decision before proceeding.")
        assessed = rank_findings(merged_findings, st.session_state.observations, st.session_state.criticality_by_asset)
        score_row = next((row for row in assessed if row.finding.asset.ip == proposal.action.target and row.finding.port in proposal.action.ports), None)
        st.markdown("**Observed facts (code generated)**")
        st.write(f"Exposure: {exposure} · Evidence IDs: {', '.join(dict.fromkeys(exposure_ids)) or 'none'}")
        st.write(f"Risk score: {score_row.priority_score if score_row and score_row.priority_score is not None else 'not scored'}")
        st.caption("Why: live open evidence contributes exposure to risk; imported evidence and missing observations do not establish live exposure.")
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
                    AUDIT.append("plan_approved", "analyst", {"action_id": proposal.action.id, "note": "Approved for analyst follow-up; imported report must still be supplied in Imports."})
                    st.session_state.plan_status = "approved"
                    st.success("Plan approved. Supply the matching Burp XML in Imports to produce findings.")
                else:
                    st.error("Plan failed the current scope check: " + checked.message)
            if right.button("Skip plan", key="skip_plan"):
                AUDIT.append("plan_skipped", "analyst", {"action_id": proposal.action.id})
                st.session_state.plan_status = "skipped"
                st.info("Plan skipped.")

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

with tabs[4]:
    st.subheader("Risk prioritization")
    findings = correlate_findings(st.session_state.raw_findings, st.session_state.observations)
    assets = sorted({item.asset.ip for item in findings})
    for asset in assets:
        previous = st.session_state.criticality_by_asset.get(asset, "medium")
        selected = st.selectbox("Asset criticality · " + asset, ["low", "medium", "high"], index=["low", "medium", "high"].index(previous), key="criticality_" + asset)
        if selected != previous:
            st.session_state.criticality_by_asset[asset] = selected
            AUDIT.append("asset_criticality_changed", "analyst", {"asset": asset, "old": previous, "new": selected})
    ranked = rank_findings(findings, st.session_state.observations, st.session_state.criticality_by_asset)
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
            report_result = generate_pdf(findings, st.session_state.observations, LEDGER, AUDIT, report_dir / "assessment.pdf", engagement=GUARD.policy.engagement, scope_cidrs=GUARD.policy.allowed_cidrs, criticality=st.session_state.criticality_by_asset)
            st.session_state.report_path = report_result["path"]
            st.session_state.report_hash = report_result["sha256"]
            st.session_state.report_status = f"Grounded findings: {report_result['grounded_findings']}/{report_result['total_findings']}"
        except Exception as exc:
            AUDIT.append("report_generation_failed", "analyst", {"reason": f"{type(exc).__name__}: {exc}"[:500]})
            st.error("Could not generate PDF report: " + str(exc))
    if st.session_state.report_path and Path(st.session_state.report_path).is_file():
        st.caption("SHA-256: " + st.session_state.report_hash)
        st.caption(st.session_state.report_status)
        st.download_button("Download PDF report", data=Path(st.session_state.report_path).read_bytes(), file_name="proofpath-assessment.pdf", mime="application/pdf")
