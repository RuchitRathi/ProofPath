"""Full-featured terminal CLI for ProofPath VAPT platform."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.selftest import run_approval_redteam, run_cases, run_grounding_redteam, run_injection_redteam
from proofpath.grounding import verify_finding, verify_text
from proofpath.schemas import Action, ActionName, Finding, ServiceObservation
from proofpath.verification import verify_report_and_approvals
from proofpath.adapters.base import execute_action
from proofpath.adapters.active_validate import ActiveValidationAdapter
from proofpath.adapters.burp_import import import_burp_xml
from proofpath.adapters.nessus_import import import_nessus_xml
from proofpath.adapters.openvas_import import import_openvas_xml
from proofpath.adapters.nikto_import import import_nikto_report
from proofpath.adapters.zap_import import import_zap_report
from proofpath.adapters.metasploit_import import import_metasploit_report
from proofpath.adapters.nmap import NmapAdapter, NmapExecutionConfig, RecordedNmapXMLAdapter
from proofpath.approval import decide_approval, request_approval
from proofpath.correlator import correlate_findings
from proofpath.diff import compare_assessments
from proofpath.integrations import INTEGRATIONS
from proofpath.normalizer import normalize_nmap_observations
from proofpath.proposer import OllamaClient, OllamaConfig, RulePlanner, propose_and_gate
from proofpath.report.generator import generate_pdf
from proofpath.report.sarif import export_sarif
from proofpath.risk import rank_findings
from proofpath.scope_guard import ScopeGuard
from proofpath.threat_intel import load_public_threat_intel

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
except Exception:
    console = None


def _print(msg: str = "", style: str = "") -> None:
    if console:
        console.print(msg, style=style) if style else console.print(msg)
    else:
        print(re.sub(r"\[.*?\]", "", msg))


def _print_header(title: str, subtitle: str = "") -> None:
    if console:
        text = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            text += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(text, border_style="blue", expand=False))
    else:
        print(f"\n=== {title} ===")
        if subtitle:
            print(subtitle)


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


def _parse_ports(text: str) -> list[int]:
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not parts:
        raise ValueError("ports are required")
    ports: list[int] = []
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"invalid port '{part}': must be integer")
        p = int(part)
        if not 1 <= p <= 65535:
            raise ValueError(f"port {p} outside valid range 1-65535")
        ports.append(p)
    return ports


# ---------------------------------------------------------------------------
# CLI Command Handlers
# ---------------------------------------------------------------------------

def handle_scan(args: argparse.Namespace) -> int:
    """Run a scoped live Nmap reconnaissance scan or import XML."""
    _print_header("ProofPath Reconnaissance & Service Discovery", f"Target: {args.target} | Ports: {args.ports}")
    scope_path = Path(args.scope)
    guard = ScopeGuard.from_yaml(scope_path)
    if getattr(args, "open_scope", False):
        guard.policy = guard.policy.model_copy(update={"allow_all_ips": True})
        _print("[yellow]Scope Guard:[/yellow] Universal IP Scope Mode active.")

    data_dir = Path(args.data)
    audit = AuditLog(data_dir / "audit.jsonl")
    ledger = Ledger(data_dir / "evidence")

    try:
        ports = _parse_ports(args.ports)
    except ValueError as e:
        _print(f"[red]Error:[/red] {e}")
        return 1

    action = Action(
        id=uuid.uuid4().hex,
        name=ActionName.NMAP_SCAN,
        target=args.target,
        ports=ports,
        arguments={
            "service_detection": True,
            "skip_host_discovery": args.skip_ping,
            "timing": 2,
            "host_timeout_seconds": 60,
        },
        engagement_id=guard.policy.engagement,
        requested_by=args.requester,
    )

    if args.import_xml:
        xml_path = Path(args.import_xml)
        if not xml_path.is_file():
            _print(f"[red]Error:[/red] Nmap XML file not found: {xml_path}")
            return 1
        raw_xml = xml_path.read_bytes()
        action.name = ActionName.IMPORT_NMAP_XML
        adapters = {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(raw_xml)}
    else:
        nmap_config = NmapExecutionConfig.from_yaml(Path("nmap.yaml") if Path("nmap.yaml").is_file() else None)
        adapters = {ActionName.NMAP_SCAN: NmapAdapter(wsl_distribution=nmap_config.distribution if nmap_config.runtime == "wsl" else None)}

    audit.append("analyst_request", args.requester, {"request": "CLI Reconnaissance scan", "target": args.target, "ports": args.ports})
    res = execute_action(action, guard, audit, ledger, adapters)

    if not res.decision.allowed:
        _print(f"[bold red]SCOPE DENIED:[/bold red] {res.decision.reason}")
        return 1

    _print(f"[green]Scope Status:[/green] Authorized · Tool Status: {res.status}")
    if res.evidence_id:
        _print(f"[cyan]Evidence ID:[/cyan] {res.evidence_id}")

    if res.services:
        _print(f"\n[bold]Discovered Services ({len(res.services)}):[/bold]")
        if console:
            tbl = Table(show_header=True, header_style="bold magenta")
            tbl.add_column("IP")
            tbl.add_column("Port")
            tbl.add_column("Protocol")
            tbl.add_column("Service")
            tbl.add_column("State")
            tbl.add_column("Product / Version")
            for svc in res.services:
                tbl.add_row(svc.ip, str(svc.port), svc.protocol, svc.service or "", svc.state, f"{svc.product or ''} {svc.version or ''}".strip())
            console.print(tbl)
        else:
            for svc in res.services:
                print(f"  {svc.ip}:{svc.port}/{svc.protocol} - {svc.service} ({svc.state}) {svc.product or ''} {svc.version or ''}".strip())
    else:
        _print("[yellow]No active services discovered for the given target and ports.[/yellow]")

    return 0


def handle_import(args: argparse.Namespace) -> int:
    """Ingest external tool vulnerability reports."""
    _print_header("ProofPath Tool Report Ingestion", f"Tool: {args.tool.upper()} | File: {args.file}")
    scope_path = Path(args.scope)
    guard = ScopeGuard.from_yaml(scope_path)
    if getattr(args, "open_scope", False):
        guard.policy = guard.policy.model_copy(update={"allow_all_ips": True})

    data_dir = Path(args.data)
    audit = AuditLog(data_dir / "audit.jsonl")
    ledger = Ledger(data_dir / "evidence")

    file_path = Path(args.file)
    if not file_path.is_file():
        _print(f"[red]Error:[/red] File not found: {file_path}")
        return 1
    raw_content = file_path.read_bytes()

    tool = args.tool.lower()
    try:
        if tool == "nessus":
            res = import_nessus_xml(raw_content, guard, audit, ledger, actor=args.requester)
        elif tool == "burp":
            res = import_burp_xml(raw_content, guard, audit, ledger, actor=args.requester)
        elif tool == "openvas":
            res = import_openvas_xml(raw_content, guard, audit, ledger, actor=args.requester)
        elif tool == "nikto":
            res = import_nikto_report(raw_content, guard, audit, ledger, actor=args.requester)
        elif tool == "zap":
            res = import_zap_report(raw_content, guard, audit, ledger, actor=args.requester)
        elif tool == "metasploit":
            res = import_metasploit_report(raw_content, guard, audit, ledger, actor=args.requester)
        else:
            _print(f"[red]Error:[/red] Unsupported tool '{tool}'. Valid: nessus, burp, openvas, nikto, zap, metasploit")
            return 1

        _print(f"[bold green]Ingestion Complete:[/bold green] {tool.upper()}")
        _print(f"  Parsed items: {res.parsed_items}")
        _print(f"  Findings stored: {len(res.findings)}")
        _print(f"  Evidence ID: {res.evidence_id}")
        if getattr(res, "dropped_items", 0) > 0 or getattr(res, "dropped_issues", 0) > 0:
            dropped = getattr(res, "dropped_items", 0) or getattr(res, "dropped_issues", 0)
            _print(f"  [yellow]Out-of-scope dropped:[/yellow] {dropped}")

        # Save cumulative findings to data/reports/current-findings.json
        findings_file = data_dir / "reports" / "current-findings.json"
        findings_file.parent.mkdir(parents=True, exist_ok=True)
        existing: list[dict] = []
        if findings_file.is_file():
            try:
                existing = json.loads(findings_file.read_text(encoding="utf-8"))
            except Exception:
                existing = []
        new_items = [f.model_dump(mode="json") for f in res.findings]
        findings_file.write_text(json.dumps(existing + new_items, indent=2), encoding="utf-8")
        _print(f"  Updated findings pool: {findings_file}")
        return 0
    except Exception as exc:
        _print(f"[bold red]Ingestion Failed:[/bold red] {exc}")
        return 1


def handle_findings(args: argparse.Namespace) -> int:
    """View and correlate findings stored in the assessment data directory."""
    _print_header("ProofPath Finding Correlation & Inspection")
    data_dir = Path(args.data)
    findings_file = data_dir / "reports" / "current-findings.json"
    if not findings_file.is_file():
        _print("[yellow]No findings file found in data directory. Run 'import' or 'demo-load' first.[/yellow]")
        return 0

    raw = json.loads(findings_file.read_text(encoding="utf-8"))
    raw_findings = [Finding.model_validate(item) for item in raw]
    findings = correlate_findings(raw_findings, [])

    _print(f"[bold]Correlated Findings ({len(findings)}):[/bold]")
    if console:
        tbl = Table(show_header=True, header_style="bold cyan")
        tbl.add_column("ID", style="bold")
        tbl.add_column("Title")
        tbl.add_column("Asset")
        tbl.add_column("Port")
        tbl.add_column("Severity")
        tbl.add_column("CVSS")
        tbl.add_column("Evidence ID")

        for f in findings:
            ev_id = f.evidence[0].evidence_id if f.evidence else "none"
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(f.severity.lower(), "white")
            tbl.add_row(f.id, f.title[:40], f.asset.ip, str(f.port), f"[{sev_style}]{f.severity.upper()}[/{sev_style}]", str(f.cvss) if f.cvss is not None else "not provided", ev_id)
        console.print(tbl)
    else:
        for f in findings:
            print(f"[{f.id}] {f.title} - {f.asset.ip}:{f.port} [{f.severity.upper()}] (CVSS: {f.cvss or 'not provided'})")

    return 0


def handle_risk(args: argparse.Namespace) -> int:
    """Compute multi-factor risk prioritization on findings."""
    _print_header("ProofPath Multi-Factor Risk Prioritization")
    data_dir = Path(args.data)
    findings_file = data_dir / "reports" / "current-findings.json"
    if not findings_file.is_file():
        _print("[yellow]No findings file found. Ingest findings first.[/yellow]")
        return 1

    raw = json.loads(findings_file.read_text(encoding="utf-8"))
    findings = correlate_findings([Finding.model_validate(item) for item in raw], [])
    ledger = Ledger(data_dir / "evidence")

    public_intel = None
    intel_dir = data_dir / "threat_intel" / "training"
    if intel_dir.is_dir():
        try:
            public_intel = load_public_threat_intel(intel_dir, ledger)
            _print(f"[dim]Threat intel active: KEV ({public_intel.kev_evidence_id}) | EPSS ({public_intel.epss_evidence_id})[/dim]")
        except Exception:
            pass

    ranked = rank_findings(findings, [], {}, public_intel)
    if console:
        tbl = Table(title="Risk Prioritization Matrix", show_header=True, header_style="bold green")
        tbl.add_column("Rank", justify="center")
        tbl.add_column("ID")
        tbl.add_column("Asset")
        tbl.add_column("Severity")
        tbl.add_column("Score", justify="right")
        tbl.add_column("Factors")
        for item in ranked:
            factors = "; ".join(f"{f.name}={f.value}" for f in item.factors if f.included)
            tbl.add_row(str(item.rank), item.finding.id, f"{item.finding.asset.ip}:{item.finding.port}", item.finding.severity.upper(), f"{item.priority_score:.1f}" if item.priority_score is not None else "N/A", factors[:50])
        console.print(tbl)
    else:
        for item in ranked:
            print(f"Rank {item.rank}: {item.finding.id} ({item.finding.asset.ip}:{item.finding.port}) - Score: {item.priority_score}")

    return 0


def handle_plan(args: argparse.Namespace) -> int:
    """Generate deterministic or Qwen AI adaptive next steps."""
    _print_header("ProofPath Adaptive Next-Step Planner")
    data_dir = Path(args.data)
    scope_path = Path(args.scope)
    guard = ScopeGuard.from_yaml(scope_path)
    audit = AuditLog(data_dir / "audit.jsonl")
    ledger = Ledger(data_dir / "evidence")

    findings_file = data_dir / "reports" / "current-findings.json"
    raw_findings = []
    if findings_file.is_file():
        raw = json.loads(findings_file.read_text(encoding="utf-8"))
        raw_findings = [Finding.model_validate(item) for item in raw]
    findings = correlate_findings(raw_findings, [])

    planner = RulePlanner()
    candidates = planner.candidates([], guard.policy.engagement, findings=findings, enabled_actions=set(guard.policy.enabled_actions))

    if not candidates:
        _print("[yellow]No follow-up action candidates generated for current findings/observations.[/yellow]")
        return 0

    _print(f"[bold]Generated Action Candidates ({len(candidates)}):[/bold]")
    for c in candidates:
        _print(f"  [{c.candidate_id}] Action: [cyan]{c.action.name.value}[/cyan] Target: {c.action.target}:{c.action.ports[0]} | Expected: {c.expected_result}")

    if args.ai:
        _print("\n[bold]Consulting Local Qwen Model for Strategic Selection...[/bold]")
        client = OllamaClient(OllamaConfig.from_yaml(Path("ollama.yaml") if Path("ollama.yaml").is_file() else None))
        proposal, gated, fallback = propose_and_gate([], candidates, client, guard, audit, ledger, findings=findings)
        if proposal:
            _print(f"[green]AI Selected Candidate:[/green] [bold]{proposal.candidate_id}[/bold]")
            _print(f"Inferred: {proposal.rationale.inferred}")
            _print(f"Scope Status: {'Authorized' if gated.allowed else 'Denied'}")

    return 0


def handle_report(args: argparse.Namespace) -> int:
    """Generate formal ReportLab PDF and OASIS SARIF v2.1.0 deliverables."""
    _print_header("ProofPath Executive & Technical Report Generator")
    data_dir = Path(args.data)
    scope_path = Path(args.scope)
    guard = ScopeGuard.from_yaml(scope_path)
    audit = AuditLog(data_dir / "audit.jsonl")
    ledger = Ledger(data_dir / "evidence")

    findings_file = data_dir / "reports" / "current-findings.json"
    if not findings_file.is_file():
        _print("[red]Error:[/red] No findings available to generate report. Ingest findings first.")
        return 1

    raw = json.loads(findings_file.read_text(encoding="utf-8"))
    findings = correlate_findings([Finding.model_validate(item) for item in raw], [])

    out_path = Path(args.output) if args.output else data_dir / "reports" / "assessment.pdf"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        report_res = generate_pdf(
            findings,
            [],
            ledger,
            audit,
            out_path,
            engagement=guard.policy.engagement,
            scope_cidrs=guard.policy.allowed_cidrs,
        )
        _print(f"[bold green]Report Generated:[/bold green] {report_res['path']}")
        _print(f"  Cryptographic SHA-256 Digest: [cyan]{report_res['sha256']}[/cyan]")
        _print(f"  Grounded findings: {report_res['grounded_findings']}/{report_res['total_findings']}")

        if args.sarif:
            sarif_path = out_path.with_suffix(".sarif")
            sarif_data = export_sarif(findings, guard.policy.engagement)
            sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
            _print(f"  [bold green]SARIF Export:[/bold green] {sarif_path}")

        return 0
    except Exception as exc:
        _print(f"[bold red]Report Generation Failed:[/bold red] {exc}")
        return 1


def handle_tools(args: argparse.Namespace) -> int:
    """Display integration capabilities matrix across all security tools."""
    _print_header("ProofPath Security Tool Integration Matrix")
    if console:
        tbl = Table(show_header=True, header_style="bold magenta")
        tbl.add_column("Tool", style="bold")
        tbl.add_column("Integration Mode")
        tbl.add_column("Description")
        for row in INTEGRATIONS:
            tbl.add_row(row["tool"], row["mode"], row.get("description", ""))
        console.print(tbl)
    else:
        for row in INTEGRATIONS:
            print(f"- {row['tool']}: {row['mode']}")
    return 0


# ---------------------------------------------------------------------------
# Main Argument Parser
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """ProofPath enterprise security CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="proofpath",
        description="ProofPath - Enterprise Auditable Security Assessment & VAPT CLI Platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. verify
    verify = sub.add_parser("verify", help="recompute and cryptographically verify the hash-chained audit log")
    verify.add_argument("--audit", required=True, help="path to audit.jsonl")
    verify.add_argument("--ledger", default="data/evidence", help="path to evidence ledger directory")

    # 2. redteam
    redteam = sub.add_parser("redteam", help="run comprehensive scope-guard bypass and adversarial safety checks")
    redteam.add_argument("--scope", default="scope.yaml")

    # 3. ground-check
    ground = sub.add_parser("ground-check", help="check current report claims against cited ledger evidence")
    ground.add_argument("--findings", default="data/reports/current-findings.json")
    ground.add_argument("--ledger", default="data/evidence")
    ground.add_argument("--audit", default="data/audit.jsonl")

    # 4. scan (live reconnaissance)
    scan_cmd = sub.add_parser("scan", help="execute scoped live Nmap reconnaissance or import recorded Nmap XML")
    scan_cmd.add_argument("--target", required=True, help="target IP or hostname")
    scan_cmd.add_argument("--ports", default="80,443,8080,8443", help="comma-separated ports (e.g. 80,443)")
    scan_cmd.add_argument("--scope", default="scope.yaml", help="path to scope.yaml")
    scan_cmd.add_argument("--data", default="data", help="data storage root directory")
    scan_cmd.add_argument("--requester", default="cli-analyst", help="analyst identity for audit log")
    scan_cmd.add_argument("--skip-ping", action="store_true", default=True, help="disable ICMP ping (-Pn)")
    scan_cmd.add_argument("--import-xml", help="import recorded Nmap XML instead of running live")
    scan_cmd.add_argument("--open-scope", action="store_true", help="enable universal IP scope mode")

    # 5. import (ingest tool report)
    import_cmd = sub.add_parser("import", help="ingest vulnerability reports from Nessus, Burp, OpenVAS, Nikto, ZAP, or Metasploit")
    import_cmd.add_argument("--tool", required=True, choices=["nessus", "burp", "openvas", "nikto", "zap", "metasploit"], help="target scanner tool name")
    import_cmd.add_argument("--file", required=True, help="path to report file (XML/JSON)")
    import_cmd.add_argument("--scope", default="scope.yaml", help="path to scope.yaml")
    import_cmd.add_argument("--data", default="data", help="data storage root directory")
    import_cmd.add_argument("--requester", default="cli-analyst", help="analyst identity for audit log")
    import_cmd.add_argument("--open-scope", action="store_true", help="enable universal IP scope mode")

    # 6. findings
    findings_cmd = sub.add_parser("findings", help="view, filter, and inspect correlated findings")
    findings_cmd.add_argument("--data", default="data", help="data storage root directory")

    # 7. risk
    risk_cmd = sub.add_parser("risk", help="compute multi-factor risk prioritization on findings")
    risk_cmd.add_argument("--data", default="data", help="data storage root directory")

    # 8. plan
    plan_cmd = sub.add_parser("plan", help="generate next-step assessment plan (rule-based or local AI)")
    plan_cmd.add_argument("--scope", default="scope.yaml")
    plan_cmd.add_argument("--data", default="data")
    plan_cmd.add_argument("--ai", action="store_true", help="consult local Qwen model for next step")

    # 9. report
    report_cmd = sub.add_parser("report", help="generate formal ReportLab PDF and OASIS SARIF v2.1.0 exports")
    report_cmd.add_argument("--data", default="data")
    report_cmd.add_argument("--scope", default="scope.yaml")
    report_cmd.add_argument("--output", help="custom output PDF path")
    report_cmd.add_argument("--sarif", action="store_true", default=True, help="also generate SARIF v2.1.0 export")

    # 10. tools
    tools_cmd = sub.add_parser("tools", help="display security tool integrations and capabilities")

    # 11. demo-load
    demo = sub.add_parser("demo-load", help="load the labeled synthetic demo dataset through guarded importers")
    demo.add_argument("--scope", default="scope.demo.yaml")
    demo.add_argument("--data", default="data/demo")
    demo.add_argument("--all-tools", action="store_true", help="import all 7 tool reports (Nmap, Nessus, Burp, OpenVAS, Nikto, ZAP, Metasploit)")

    # 12. agent-run
    agent_cmd = sub.add_parser("agent-run", help="run the autonomous VAPT agent ReAct loop")
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

    if args.command == "scan":
        return handle_scan(args)
    if args.command == "import":
        return handle_import(args)
    if args.command == "findings":
        return handle_findings(args)
    if args.command == "risk":
        return handle_risk(args)
    if args.command == "plan":
        return handle_plan(args)
    if args.command == "report":
        return handle_report(args)
    if args.command == "tools":
        return handle_tools(args)

    if args.command == "ground-check":
        findings_path = Path(args.findings)
        if not findings_path.is_file():
            print(f"current report findings were not found: {findings_path}")
            return 1
        try:
            raw = json.loads(findings_path.read_text(encoding="utf-8"))
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
        request = Action(id="demo-import-nmap", name=ActionName.IMPORT_NMAP_XML, target="10.20.0.10", ports=[80], engagement_id=guard.policy.engagement, requested_by="demo-loader")
        nmap_result = execute_action(request, guard, audit, ledger, {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(nmap_raw)})
        nessus = import_nessus_xml((fixture / "nessus.nessus").read_bytes(), guard, audit, ledger, actor="demo-loader")
        burp = import_burp_xml((fixture / "burp.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
        all_raw_findings = [*nessus.findings, *burp.findings]

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
        findings_file = data / "reports" / "current-findings.json"
        findings_file.parent.mkdir(parents=True, exist_ok=True)
        findings_file.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
        (data / "current-findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")

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
                    "action_type": proposal.action.name.value,
                    "target": proposal.action.target,
                    "port": proposal.action.ports[0],
                    "allowed_by_guard": gated.decision.allowed if gated else False,
                    "rationale": {
                        "observed": proposal.rationale.observed,
                        "inferred": proposal.rationale.inferred,
                        "why": proposal.rationale.why,
                    },
                    "grounding_valid": grounding.accepted,
                    "grounding_violations": list(grounding.violations),
                    "fallback_used": fallback,
                    "audit_events": [item.event_type for item in proposal_events],
                }
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "agent-run":
        from proofpath.agent import AgentConfig, VAPTAgent
        from proofpath.selftest import demo_resolver

        scope = Path(args.scope)
        data = Path(args.data)
        data.mkdir(parents=True, exist_ok=True)
        guard = ScopeGuard.from_yaml(scope, resolver=demo_resolver)
        audit = AuditLog(data / "audit.jsonl")
        ledger = Ledger(data / "evidence")

        fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "demo"
        nmap_raw = (fixture / "nmap.xml").read_bytes()
        request = Action(
            id="demo-import-nmap",
            name=ActionName.IMPORT_NMAP_XML,
            target="10.20.0.10",
            ports=[80],
            engagement_id=guard.policy.engagement,
            requested_by="demo-loader",
        )
        nmap_result = execute_action(
            request, guard, audit, ledger,
            {ActionName.IMPORT_NMAP_XML: RecordedNmapXMLAdapter(nmap_raw)},
        )
        observations = list(normalize_nmap_observations(nmap_result.services))
        nessus = import_nessus_xml((fixture / "nessus.nessus").read_bytes(), guard, audit, ledger, actor="demo-loader")
        burp = import_burp_xml((fixture / "burp.xml").read_bytes(), guard, audit, ledger, actor="demo-loader")
        all_raw_findings = [*nessus.findings, *burp.findings]

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

        agent_config = AgentConfig(
            max_steps=args.max_steps,
            auto_execute_nmap=args.auto_nmap,
            require_human_approval_for_active=True,
            engagement_id=guard.policy.engagement,
        )
        agent = VAPTAgent(guard, audit, ledger, {}, agent_config)
        agent.load_state(observations=observations, findings=all_raw_findings)

        print(f"Agent starting: {len(observations)} observations, {len(all_raw_findings)} raw findings")
        agent_result = agent.run()

        print(f"\nAgent completed: status={agent_result.status}, steps={len(agent_result.steps)}, "
              f"observations={agent_result.total_observations}, findings={agent_result.total_findings}, "
              f"duration={agent_result.duration_seconds:.1f}s")
        if agent_result.plan:
            print(f"\nPlan: {agent_result.plan.reasoning}")
        for step in agent_result.steps:
            icon = {"observe": "[OBSERVE]", "think": "[THINK]", "act": "[ACT]", "reflect": "[REFLECT]",
                    "import_request": "[IMPORT]", "complete": "[DONE]", "error": "[ERROR]"}.get(step.step_type.value, "•")
            action_info = f" {step.action_name}" if step.action_name else ""
            target_info = f" {step.target}" if step.target else ""
            print(f"  {icon} Step {step.step_number} [{step.step_type.value}]{action_info}{target_info}: {step.reasoning[:120]}")
        if agent_result.import_requests:
            print(f"\nPending import requests ({len(agent_result.import_requests)}):")
            for req in agent_result.import_requests:
                print(f"  Report: {req.tool} for {req.target}:{','.join(str(p) for p in req.ports)} — {req.reason[:80]}")

        (data / "agent-trace.json").write_text(agent_result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nAgent trace saved to {data / 'agent-trace.json'}")
        return 0

    # redteam fallback
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


if __name__ == "__main__":
    raise SystemExit(main())
