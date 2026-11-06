"""Command line helpers: verify the audit chain, or run scope bypass checks."""

from __future__ import annotations

import argparse
from pathlib import Path

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.selftest import run_approval_redteam, run_cases, run_grounding_redteam, run_injection_redteam
from proofpath.grounding import verify_finding
from proofpath.schemas import Finding
from proofpath.verification import verify_report_and_approvals


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
