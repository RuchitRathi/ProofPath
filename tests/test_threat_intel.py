from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.threat_intel import load_public_threat_intel, parse_epss, parse_kev, parse_nvd_response


def test_parsers_accept_public_feed_shapes_and_keep_source_values() -> None:
    kev_raw = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "requiredAction": "Patch"}]}).encode()
    epss_raw = gzip.compress(b"# model version test\ncve,epss,percentile\nCVE-2021-44228,0.97,0.99\n")
    nvd_raw = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "version": "3.1"}}]}}}]}).encode()

    assert parse_kev(kev_raw)["CVE-2021-44228"].date_added == "2021-12-10"
    assert parse_epss(epss_raw)["CVE-2021-44228"].probability == 0.97
    nvd = parse_nvd_response(nvd_raw, "EV-0001")["CVE-2021-44228"]
    assert nvd.cvss == 10.0 and nvd.evidence_id == "EV-0001"


def test_public_feed_loader_requires_matching_ledger_hashes(tmp_path: Path) -> None:
    repo = tmp_path
    cache = repo / "data" / "threat_intel" / "training"
    cache.mkdir(parents=True)
    kev_path = cache / "known_exploited_vulnerabilities.json"
    epss_path = cache / "epss-current.csv.gz"
    kev_raw = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "requiredAction": "Patch"}]}).encode()
    epss_raw = gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n")
    kev_path.write_bytes(kev_raw)
    epss_path.write_bytes(epss_raw)

    ledger = Ledger(repo / "data" / "evidence")
    kev_evidence = ledger.store(content=kev_raw, tool="cisa_kev", command=["GET", "https://example.invalid/kev"], status="ok", summary="test public feed", source_mode="imported")
    epss_evidence = ledger.store(content=epss_raw, tool="first_epss", command=["GET", "https://example.invalid/epss"], status="ok", summary="test public feed", source_mode="imported")
    metrics = {
        "data_sources": {
            "cisa_kev": {"path": "data/threat_intel/training/known_exploited_vulnerabilities.json", "sha256": hashlib.sha256(kev_raw).hexdigest(), "evidence_id": kev_evidence.id},
            "first_epss_current": {"path": "data/threat_intel/training/epss-current.csv.gz", "sha256": hashlib.sha256(epss_raw).hexdigest(), "evidence_id": epss_evidence.id},
        }
    }
    (cache / "training_metrics.json").write_text(json.dumps(metrics), encoding="utf-8")

    loaded = load_public_threat_intel(cache, ledger, repository_root=repo)
    assert loaded is not None
    assert loaded.kev_evidence_id == kev_evidence.id
    assert loaded.epss["CVE-2021-44228"].probability == 0.97

    epss_path.write_bytes(epss_raw + b"tampered")
    with pytest.raises(ValueError, match="cache hash"):
        load_public_threat_intel(cache, ledger, repository_root=repo)
