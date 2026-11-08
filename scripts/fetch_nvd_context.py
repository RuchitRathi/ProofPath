"""Fetch NVD CVE metadata for explicit CVE IDs or a findings JSON file.

This performs read-only public metadata requests, not target scans. Responses,
SHA-256 metadata, and audit entries are written under the project data/ tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESPONSE_BYTES = 2_000_000


def _collect_cves(findings_path: Path | None, explicit: list[str]) -> list[str]:
    cves = {item.strip().upper() for item in explicit if CVE_RE.fullmatch(item.strip().upper())}
    if findings_path is not None:
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("findings JSON must be a list")
        for finding in payload:
            if not isinstance(finding, dict) or not isinstance(finding.get("cves", []), list):
                continue
            cves.update(str(item).upper() for item in finding["cves"] if isinstance(item, str) and CVE_RE.fullmatch(item.upper()))
    return sorted(cves)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, help="JSON list of ProofPath findings")
    parser.add_argument("--cve", action="append", default=[], help="explicit public CVE identifier; may be repeated")
    parser.add_argument("--force", action="store_true", help="replace existing cache entries with current NVD responses")
    args = parser.parse_args(argv)
    try:
        cves = _collect_cves(args.findings, args.cve)
        if not cves:
            raise ValueError("no valid CVE IDs were supplied")
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if not api_key and len(cves) > 5:
            raise ValueError("without NVD_API_KEY, limit each run to five CVEs to respect NVD's unauthenticated request rate")
        cache_root = ROOT / "data" / "threat_intel" / "training" / "nvd"
        cache_root.mkdir(parents=True, exist_ok=True)
        audit = AuditLog(ROOT / "data" / "audit.jsonl")
        ledger = Ledger(ROOT / "data" / "evidence")
        fetched = 0
        skipped = 0
        for index, cve in enumerate(cves):
            raw_path = cache_root / f"{cve}.json"
            meta_path = cache_root / f"{cve}.meta.json"
            if raw_path.is_file() and meta_path.is_file() and not args.force:
                skipped += 1
                continue
            if index and not api_key:
                time.sleep(6.2)
            query = urllib.parse.urlencode({"cveId": cve})
            url = f"{NVD_API}?{query}"
            request = urllib.request.Request(url, headers={"User-Agent": "ProofPath-public-risk-research/1.0"})
            if api_key:
                request.add_header("apiKey", api_key)
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError(f"NVD response for {cve} exceeded the 2 MB limit")
            evidence = ledger.store(content=raw, tool="nvd_cve_api", command=["GET", url], status="ok", summary=f"NVD public CVE metadata response for {cve}", source_mode="imported")
            raw_path.write_bytes(raw)
            meta = {
                "cve": cve,
                "url": url,
                "evidence_id": evidence.id,
                "sha256": evidence.sha256,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            audit.append("public_intel_snapshot_loaded", "public-intel-updater", {"source": "NVD CVE API", "cve": cve, "url": url, "evidence_id": evidence.id, "sha256": evidence.sha256})
            print(f"stored {cve}: {evidence.id} sha256={evidence.sha256}")
            fetched += 1
        print(f"NVD requests stored: {fetched}; cached: {skipped}; CVEs requested: {len(cves)}")
        return 0
    except Exception as exc:
        print(f"NVD enrichment failed safely: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
