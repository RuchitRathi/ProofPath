"""Read-only public CVE threat context, kept separate from scanner findings."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from proofpath.ledger import Ledger

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class KevRecord:
    date_added: str
    required_action: str


@dataclass(frozen=True)
class EpssRecord:
    probability: float
    percentile: float


@dataclass(frozen=True)
class NvdRecord:
    cvss: float | None
    severity: str | None
    version: str | None
    evidence_id: str


@dataclass(frozen=True)
class PublicThreatIntel:
    fetched_at: str
    kev: dict[str, KevRecord] = field(default_factory=dict)
    epss: dict[str, EpssRecord] = field(default_factory=dict)
    nvd: dict[str, NvdRecord] = field(default_factory=dict)
    kev_evidence_id: str = ""
    epss_evidence_id: str = ""


def parse_kev(raw: bytes) -> dict[str, KevRecord]:
    """Parse the CISA KEV catalog and discard malformed rows."""
    payload = json.loads(raw.decode("utf-8"))
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("CISA KEV catalog has no vulnerabilities list")
    records: dict[str, KevRecord] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID", "")).strip().upper()
        date_added = row.get("dateAdded")
        required_action = row.get("requiredAction", "")
        if CVE_RE.fullmatch(cve) and isinstance(date_added, str):
            records[cve] = KevRecord(date_added=date_added, required_action=str(required_action)[:1000])
    return records


def parse_epss(raw: bytes) -> dict[str, EpssRecord]:
    """Parse FIRST's current or historical gzip CSV snapshot."""
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8-sig")
    lines = (line for line in io.StringIO(text) if not line.startswith("#"))
    reader = csv.DictReader(lines)
    if not {"cve", "epss", "percentile"}.issubset(reader.fieldnames or set()):
        raise ValueError("EPSS CSV is missing required cve/epss/percentile columns")
    records: dict[str, EpssRecord] = {}
    for row in reader:
        cve = str(row.get("cve", "")).strip().upper()
        if not CVE_RE.fullmatch(cve):
            continue
        try:
            probability = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= probability <= 1 and 0 <= percentile <= 1:
            records[cve] = EpssRecord(probability=probability, percentile=percentile)
    return records


def parse_nvd_response(raw: bytes, evidence_id: str) -> dict[str, NvdRecord]:
    """Extract NVD CVSS context without rewriting scanner-reported finding fields."""
    payload = json.loads(raw.decode("utf-8"))
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("NVD response has no vulnerabilities list")
    result: dict[str, NvdRecord] = {}
    metric_preference = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for wrapper in rows:
        cve = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
        cve_id = str(cve.get("id", "")).upper() if isinstance(cve, dict) else ""
        if not CVE_RE.fullmatch(cve_id):
            continue
        metrics = cve.get("metrics", {})
        score: float | None = None
        severity: str | None = None
        version: str | None = None
        for metric_name in metric_preference:
            entries = metrics.get(metric_name)
            if not isinstance(entries, list) or not entries:
                continue
            metric = entries[0]
            cvss_data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
            try:
                candidate = float(cvss_data["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= candidate <= 10:
                continue
            score = candidate
            severity_value = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            severity = str(severity_value).lower() if severity_value else None
            version_value = cvss_data.get("version")
            version = str(version_value) if version_value else None
            break
        result[cve_id] = NvdRecord(cvss=score, severity=severity, version=version, evidence_id=evidence_id)
    return result


def load_public_threat_intel(
    data_root: str | Path,
    ledger: Ledger,
    *,
    repository_root: str | Path | None = None,
) -> PublicThreatIntel | None:
    """Load the latest CISA/EPSS snapshots only when their ledger hashes verify."""
    root = Path(data_root)
    metrics_path = root / "training_metrics.json"
    if not metrics_path.is_file():
        return None
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    sources = metrics.get("data_sources", {})
    kev_source = sources.get("cisa_kev", {})
    epss_source = sources.get("first_epss_current", {})
    if not isinstance(kev_source, dict) or not isinstance(epss_source, dict):
        return None
    kev_path = Path(kev_source.get("path", ""))
    epss_path = Path(epss_source.get("path", ""))
    repo_root = Path(repository_root).resolve() if repository_root is not None else Path(__file__).resolve().parents[2]
    if not kev_path.is_absolute():
        kev_path = repo_root / kev_path
    if not epss_path.is_absolute():
        epss_path = repo_root / epss_path
    if not kev_path.is_file() or not epss_path.is_file():
        return None
    kev_raw = kev_path.read_bytes()
    epss_raw = epss_path.read_bytes()
    if hashlib.sha256(kev_raw).hexdigest() != kev_source.get("sha256") or hashlib.sha256(epss_raw).hexdigest() != epss_source.get("sha256"):
        raise ValueError("public threat-intel cache hash does not match training manifest")
    kev_id = str(kev_source.get("evidence_id", ""))
    epss_id = str(epss_source.get("evidence_id", ""))
    for evidence_id, expected_tool in ((kev_id, "cisa_kev"), (epss_id, "first_epss")):
        if not evidence_id:
            raise ValueError(f"{expected_tool} cache is missing its ledger evidence ID")
        record = ledger.load(evidence_id)
        if record.tool != expected_tool or not ledger.verify_artifact(evidence_id):
            raise ValueError(f"{expected_tool} ledger evidence failed verification")
    try:
        fetched_at = max(ledger.load(kev_id).captured_at, ledger.load(epss_id).captured_at).isoformat()
    except ValueError:
        fetched_at = "unknown"
    nvd_records: dict[str, NvdRecord] = {}
    nvd_dir = root / "nvd"
    if nvd_dir.is_dir():
        for metadata_path in sorted(nvd_dir.glob("CVE-*.meta.json")):
            cve = metadata_path.name.removesuffix(".meta.json").upper()
            json_path = metadata_path.with_name(cve + ".json")
            if not CVE_RE.fullmatch(cve) or not json_path.is_file():
                continue
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            evidence_id = str(metadata.get("evidence_id", ""))
            if not evidence_id:
                continue
            nvd_raw = json_path.read_bytes()
            if hashlib.sha256(nvd_raw).hexdigest() != metadata.get("sha256"):
                raise ValueError(f"NVD cache hash mismatch for {cve}")
            record = ledger.load(evidence_id)
            if record.tool != "nvd_cve_api" or record.sha256 != metadata.get("sha256") or not ledger.verify_artifact(evidence_id):
                continue
            nvd_records.update(parse_nvd_response(nvd_raw, evidence_id))
    return PublicThreatIntel(
        fetched_at=fetched_at,
        kev=parse_kev(kev_raw),
        epss=parse_epss(epss_raw),
        nvd=nvd_records,
        kev_evidence_id=kev_id,
        epss_evidence_id=epss_id,
    )
