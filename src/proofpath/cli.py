"""Command line helpers: verify the audit chain, or run scope bypass checks."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.selftest import run_approval_redteam, run_cases, run_grounding_redteam, run_injection_redteam
from proofpath.grounding import verify_finding, verify_text
from proofpath.schemas import Finding
from proofpath.verification import verify_report_and_approvals
from proofpath.adapters.base import execute_action
from proofpath.adapters.burp_import import import_burp_xml
from proofpath.adapters.nessus_import import import_nessus_xml
from proofpath.adapters.nmap import RecordedNmapXMLAdapter
from proofpath.correlator import correlate_findings
from proofpath.normalizer import normalize_nmap_observations
from proofpath.proposer import OllamaClient, OllamaConfig, RulePlanner, propose_and_gate
from proofpath.risk import rank_findings
from proofpath.scope_guard import ScopeGuard


def main(argv: list[str] | None = None) -> int:
    """Run `verify` or `redteam`. Returns a process exit code."""
    parser = argparse.ArgumentParser(prog="proofpath")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="recompute the hash-chained audit log")
    verify.add_argument("--audit", required=True)
    verify.add_argument("--ledger", default="data/evidence")
    redteam = sub.add_parser("redteam", help="run local scope-guard bypass checks")
    redteam.add_argument("--scope", default="scope.yaml")
    ground = sub.add_parser("ground-check", help="check current report claims against cited ledger evidence")
    ground.add_argument("--findings", default="data/reports/current-findings.json")
    ground.add_argument("--ledger", default="data/evidence")
    ground.add_argument("--audit", default="data/audit.jsonl")
    demo = sub.add_parser("demo-load", help="load the labeled synthetic demo dataset through guarded importers")
    demo.add_argument("--scope", default="scope.demo.yaml")
    demo.add_argument("--data", default="data/demo")
    demo.add_argument("--all-tools", action="store_true", help="import all 7 tool reports (Nmap, Nessus, Burp, OpenVAS, Nikto, ZAP, Metasploit)")
    agent_cmd = sub.add_parser("agent-run", help="run the autonomous VAPT agent on the demo dataset")
    agent_cmd.add_argument("--scope", default="scope.demo.yaml")
    agent_cmd.add_argument("--data", default="data/agent")
    agent_cmd.add_argument("--max-steps", type=int, default=15)
    agent_cmd.add_argument("--auto-nmap", action="store_true", help="auto-execute Nmap scans")
    agent_cmd.add_argument("--all-tools", action="store_true", help="import all 7 tool reports before agent run")
    args = parser.parse_args(argv)
    if args.command == "verify":
        path = Path(args.audit)
        if not path.is_file():
            print("audit log was not found")
            return 1
        try:
            entries = AuditLog(path).read_entries()
            ok, message = AuditLog(path).verify()
        except Exception as exc:
            print(str(exc))
            return 1
        if not ok:
            print(message)
            return 1
        ledger_ok, ledger_message, known = Ledger(args.ledger).verify_all()
        if not ledger_ok:
            print(ledger_message)
            return 1
        for entry in entries:
            ids = _evidence_ids(entry.details)
            for evidence_id in ids:
                if evidence_id not in known:
                    print(f"audit seq {entry.seq} cites missing evidence ID {evidence_id}")
                    return 1
        extra_ok, extra_message = verify_report_and_approvals(entries, known, Ledger(args.ledger))
        if not extra_ok:
            print(extra_message)
            return 1
        print("audit chain intact; " + ledger_message + "; all cited evidence IDs exist; " + extra_message)
        return 0
    if args.command == "ground-check":
        findings_path = Path(args.findings)
        if not findings_path.is_file():
            print(f"current report findings were not found: {findings_path}")
            return 1
        try:
            raw = __import__("json").loads(findings_path.read_text(encoding="utf-8"))
            findings = [Finding.model_validate(item) for item in raw]
            ledger = Ledger(args.ledger)
            audit = AuditLog(args.audit)
            failed = 0
            for finding in findings:
                result = verify_finding(finding, ledger, audit)
                print(f"{'PASS' if result.accepted else 'FAIL'} {finding.id}: {'grounded' if result.accepted else '; '.join(result.violations)}")
                failed += not result.accepted
            print(f"{len(findings) - failed} passed, {failed} failed")
            return 0 if failed == 0 else 1
        except Exception as exc:
            print(f"ground-check error: {exc}")
            return 1
    if args.command == "demo-load":
        from proofpath.selftest import demo_resolver
        scope = Path(args.scope)
        data = Path(args.data)
        guard = ScopeGuard.from_yaml(scope, resolver=demo_resolver)
        audit = AuditLog(data / "audit.jsonl")
        ledger = Ledger(data / "evidence")
        fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "demo"
        nmap_raw = (fixture / "nmap.xml").read_bytes()
        action = __import__("proofpath.schemas", fromlist=["Action", "ActionName"])
        request = action.Action(id="demo-import-nmap", name=action.ActionName.IMPORT_NMAP_XML, target="10.20.0.10", ports=[80], engagement_id=guard.policy.engagement, requested_by="demo-loader")
        nmap_result = execute_action(request, guard, audit, ledger, {action.ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(nmap_raw)})
        nessus = import_nessus_xml((fixture / "nessus.nessus").read_bytes(), guard, audit, ledger, actor="demo-loader")
        burp = import_burp_xml((fixture / "burp.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
        all_raw_findings = [*nessus.findings, *burp.findings]

        if getattr(args, "all_tools", False):
            from proofpath.adapters.openvas_import import import_openvas_xml
            from proofpath.adapters.nikto_import import import_nikto_report
            from proofpath.adapters.zap_import import import_zap_report
            from proofpath.adapters.metasploit_import import import_metasploit_report

            if (fixture / "openvas.xml").is_file():
                ov = import_openvas_xml((fixture / "openvas.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(ov.findings)
            if (fixture / "nikto.json").is_file():
                nk = import_nikto_report((fixture / "nikto.json").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(nk.findings)
            if (fixture / "zap.xml").is_file():
                zp = import_zap_report((fixture / "zap.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(zp.findings)
            if (fixture / "metasploit.xml").is_file():
                ms = import_metasploit_report((fixture / "metasploit.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(ms.findings)

        observations = normalize_nmap_observations(nmap_result.services)
        findings = correlate_findings(all_raw_findings, observations)
        ranked = rank_findings(findings, observations)
        planner = RulePlanner()
        candidates = planner.candidates(
            observations,
            guard.policy.engagement,
            findings=findings,
            enabled_actions=set(guard.policy.enabled_actions),
        )
        result = {"source": "SYNTHETIC / imported", "nmap_evidence_id": nmap_result.evidence_id, "observations": len(observations), "findings": len(findings), "dropped_nessus": nessus.dropped_items, "dropped_burp": burp.dropped_issues, "ranked": [{"id": row.finding.id, "rank": row.rank, "score": row.priority_score, "status": row.finding.status} for row in ranked], "candidates": [{"candidate_id": c.candidate_id, "action_type": c.action.name.value, "target": c.action.target, "port": c.action.ports[0], "exposure_state": c.exposure_state, "risk_score": c.risk_score, "risk_factors": c.risk_factors, "expected_result": c.expected_result, "evidence_ids": c.observed_evidence_ids} for c in candidates]}
        if candidates:
            client = OllamaClient(OllamaConfig.from_yaml("ollama.yaml"))
            proposal_audit_start = len(audit.read_entries())
            proposal, gated, fallback = propose_and_gate(observations, candidates, client, guard, audit, ledger, findings=findings)
            proposal_events = audit.read_entries()[proposal_audit_start:]
            if proposal:
                rationale_text = " ".join([
                    *proposal.rationale.observed,
                    proposal.rationale.inferred,
                    proposal.rationale.why,
                ])
                cited_ids = list(dict.fromkeys(re.findall(r"\bEV-\d+\b", rationale_text)))
                grounding = verify_text(rationale_text, cited_ids, ledger)
                result["proposal"] = {
                    "candidate_id": proposal.candidate_id,
                    "action": proposal.action.model_dump(mode="json"),
                    "rationale": proposal.rationale.model_dump(mode="json") if grounding.accepted else None,
                    "rationale_grounding": {"accepted": grounding.accepted, "violations": list(grounding.violations)},
                    "fallback": fallback,
                    "model_call_count": sum(entry.event_type == "model_call_metrics" for entry in proposal_events),
                    "rejected_model_outputs": [entry.details.get("reason", "") for entry in proposal_events if entry.event_type == "model_output_rejected"],
                    "guard_allowed": gated.decision.allowed if gated else False,
                    "model_metrics": client.last_metrics,
                }
            else:
                result["proposal"] = None
        data.mkdir(parents=True, exist_ok=True)
        (data / "current-findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "agent-run":
        from proofpath.agent import AgentConfig, VAPTAgent
        from proofpath.selftest import demo_resolver
        from proofpath.adapters.openvas_import import import_openvas_xml
        from proofpath.adapters.nikto_import import import_nikto_report
        from proofpath.adapters.zap_import import import_zap_report
        from proofpath.adapters.metasploit_import import import_metasploit_report

        scope = Path(args.scope)
        data = Path(args.data)
        data.mkdir(parents=True, exist_ok=True)
        guard = ScopeGuard.from_yaml(scope, resolver=demo_resolver)
        audit = AuditLog(data / "audit.jsonl")
        ledger = Ledger(data / "evidence")
        fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "demo"

        # Phase 1: Import base data to seed the agent
        action = __import__("proofpath.schemas", fromlist=["Action", "ActionName"])
        nmap_raw = (fixture / "nmap.xml").read_bytes()
        request = action.Action(
            id="demo-import-nmap",
            name=action.ActionName.IMPORT_NMAP_XML,
            target="10.20.0.10",
            ports=[80],
            engagement_id=guard.policy.engagement,
            requested_by="demo-loader",
        )
        nmap_result = execute_action(request, guard, audit, ledger, {action.ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(nmap_raw)})
        observations = normalize_nmap_observations(nmap_result.services)
        all_raw_findings: list = []

        nessus = import_nessus_xml((fixture / "nessus.nessus").read_bytes(), guard, audit, ledger, actor="demo-loader")
        burp = import_burp_xml((fixture / "burp.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
        all_raw_findings.extend(nessus.findings)
        all_raw_findings.extend(burp.findings)

        if getattr(args, "all_tools", False):
            if (fixture / "openvas.xml").is_file():
                ov = import_openvas_xml((fixture / "openvas.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(ov.findings)
            if (fixture / "nikto.json").is_file():
                nk = import_nikto_report((fixture / "nikto.json").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(nk.findings)
            if (fixture / "zap.xml").is_file():
                zp = import_zap_report((fixture / "zap.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(zp.findings)
            if (fixture / "metasploit.xml").is_file():
                ms = import_metasploit_report((fixture / "metasploit.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
                all_raw_findings.extend(ms.findings)

        # Phase 2: Configure and run the agent
        client = None
        try:
            client = OllamaClient(OllamaConfig.from_yaml("ollama.yaml"))
        except Exception:
            pass

        agent_config = AgentConfig(
            max_steps=args.max_steps,
            auto_execute_nmap=getattr(args, "auto_nmap", False),
            pause_for_imports=True,
            model_client=client,
        )
        agent = VAPTAgent(guard, audit, ledger, {}, agent_config)
        agent.load_state(observations=observations, findings=all_raw_findings)

        print(f"Agent starting: {len(observations)} observations, {len(all_raw_findings)} raw findings")
        agent_result = agent.run()

        # Phase 3: Output results
        print(f"\nAgent completed: status={agent_result.status}, steps={len(agent_result.steps)}, "
              f"observations={agent_result.total_observations}, findings={agent_result.total_findings}, "
              f"duration={agent_result.duration_seconds:.1f}s")
        if agent_result.plan:
            print(f"\nPlan: {agent_result.plan.reasoning}")
        for step in agent_result.steps:
            icon = {"observe": "🔍", "think": "🧠", "act": "⚡", "reflect": "💭",
                    "import_request": "📥", "complete": "✅", "error": "❌"}.get(step.step_type.value, "•")
            action_info = f" {step.action_name}" if step.action_name else ""
            target_info = f" {step.target}" if step.target else ""
            print(f"  {icon} Step {step.step_number} [{step.step_type.value}]{action_info}{target_info}: {step.reasoning[:120]}")
        if agent_result.import_requests:
            print(f"\nPending import requests ({len(agent_result.import_requests)}):")
            for req in agent_result.import_requests:
                print(f"  📄 {req.tool} for {req.target}:{','.join(str(p) for p in req.ports)} — {req.reason[:80]}")

        # Save agent trace
        (data / "agent-trace.json").write_text(agent_result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nAgent trace saved to {data / 'agent-trace.json'}")
        return 0
    scope = Path(args.scope)
    if not scope.is_file():
        print("scope file was not found")
        return 1
    failed = 0
    results = run_cases(scope)
    for name, ok, reason in results:
        label = "PASS" if ok else "FAIL"
        print(f"{label} {name}: {reason}")
        if not ok:
            failed += 1
    injection_ok, injection_message = run_injection_redteam(scope)
    print(f"{'PASS' if injection_ok else 'FAIL'} model injection: {injection_message}")
    if not injection_ok:
        failed += 1
    approval_results = run_approval_redteam(scope)
    for name, ok, message in approval_results:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {message}")
        failed += not ok
    grounding_results = run_grounding_redteam()
    for name, ok, message in grounding_results:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {message}")
        failed += not ok
    total = len(results) + 1 + len(approval_results) + len(grounding_results)
    print(f"{total - failed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def _evidence_ids(value: object) -> set[str]:
    if isinstance(value, dict):
        found = set()
        for key, item in value.items():
            if key == "evidence_id" and isinstance(item, str):
                found.add(item)
            found.update(_evidence_ids(item))
        return found
    if isinstance(value, list):
        return set().union(*(_evidence_ids(item) for item in value)) if value else set()
    return set()


if __name__ == "__main__":
    raise SystemExit(main())
