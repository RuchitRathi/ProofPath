"""Train an offline CVE prioritization experiment from public EPSS/KEV history.

The target is deliberately narrow: whether CISA adds a CVE to KEV within 90
days after an EPSS snapshot. It is not a vulnerability detector and KEV
absence is not proof that a vulnerability was never exploited.

All downloads and generated files stay under the repository's ignored data/.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import random
import re
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
DATA_ROOT = ROOT / "data" / "threat_intel" / "training"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_RAW = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{year}/epss_scores-{day}.csv.gz"
EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
SNAPSHOT_DATES = [
    "2025-04-01", "2025-05-01", "2025-06-01", "2025-07-01", "2025-08-01", "2025-09-01",
    "2026-01-01", "2026-02-01", "2026-03-01", "2026-04-01", "2026-05-01", "2026-06-01",
]
TRAIN_CUTOFF = date(2025, 9, 1)
TEST_START = date(2026, 1, 1)
HORIZON_DAYS = 90
MAX_NEGATIVE_RATIO = 200
CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


def _download(url: str, destination: Path, *, force: bool = False) -> tuple[int, str]:
    """Download one public source to a repository-local cache atomically."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and destination.stat().st_size and not force:
        raw = destination.read_bytes()
        return len(raw), hashlib.sha256(raw).hexdigest()
    request = urllib.request.Request(url, headers={"User-Agent": "ProofPath-public-risk-research/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError(f"source exceeded the 32 MiB per-file limit: {url}")
    if not raw:
        raise ValueError(f"empty response from {url}")
    part = destination.with_suffix(destination.suffix + ".part")
    part.write_bytes(raw)
    part.replace(destination)
    return len(raw), hashlib.sha256(raw).hexdigest()


def _read_epss(path: Path, snapshot: date, kev_dates: dict[str, date]) -> tuple[list[list[float]], list[int], list[float], int, int]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        lines = (line for line in stream if not line.startswith("#"))
        reader = csv.DictReader(lines)
        required = {"cve", "epss", "percentile"}
        if not required.issubset(reader.fieldnames or set()):
            raise ValueError(f"unexpected EPSS columns in {path.name}")

        positive_count = sum(
            snapshot < added <= snapshot + timedelta(days=HORIZON_DAYS)
            for added in kev_dates.values()
        )
        negative_cap = max(500, positive_count * MAX_NEGATIVE_RATIO)
        rng = random.Random(snapshot.isoformat())
        features: list[list[float]] = []
        labels: list[int] = []
        weights: list[float] = []
        negative_reservoir: list[tuple[list[float], int]] = []
        negative_total = 0
        positives_seen = 0

        for row in reader:
            cve = str(row.get("cve", "")).strip().upper()
            match = CVE_RE.fullmatch(cve)
            if not match:
                continue
            try:
                epss = float(row["epss"])
                percentile = float(row["percentile"])
            except (KeyError, TypeError, ValueError):
                continue
            if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
                continue
            cve_year = int(match.group(1))
            if cve_year < 1999 or cve_year > snapshot.year:
                continue
            age_days = max(0, (snapshot - date(cve_year, 1, 1)).days)
            vector = [epss, percentile, float(cve_year), float(age_days)]
            added = kev_dates.get(cve)
            positive = added is not None and snapshot < added <= snapshot + timedelta(days=HORIZON_DAYS)
            if positive:
                features.append(vector)
                labels.append(1)
                weights.append(1.0)
                positives_seen += 1
                continue

            negative_total += 1
            if len(negative_reservoir) < negative_cap:
                negative_reservoir.append((vector, 0))
            else:
                position = rng.randrange(negative_total)
                if position < negative_cap:
                    negative_reservoir[position] = (vector, 0)

        negative_weight = negative_total / len(negative_reservoir) if negative_reservoir else 1.0
        for vector, label in negative_reservoir:
            features.append(vector)
            labels.append(label)
            weights.append(negative_weight)
        return features, labels, weights, positives_seen, negative_total


def _load_kevs(raw: bytes) -> dict[str, date]:
    payload = json.loads(raw.decode("utf-8"))
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list):
        raise ValueError("CISA KEV response has no vulnerabilities list")
    result: dict[str, date] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID", "")).strip().upper()
        added = row.get("dateAdded")
        if not CVE_RE.fullmatch(cve) or not isinstance(added, str):
            continue
        try:
            result[cve] = date.fromisoformat(added)
        except ValueError:
            continue
    return result


def _weighted_metrics(labels: list[int], scores: list[float], weights: list[float]) -> dict[str, float]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    if len(set(labels)) < 2:
        return {"average_precision": 0.0, "roc_auc": 0.0}
    return {
        "average_precision": float(average_precision_score(labels, scores, sample_weight=weights)),
        "roc_auc": float(roc_auc_score(labels, scores, sample_weight=weights)),
    }


def main() -> int:
    from sklearn.ensemble import HistGradientBoostingClassifier
    import joblib
    from proofpath.audit import AuditLog
    from proofpath.ledger import Ledger

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(ROOT / "data" / "audit.jsonl")
    ledger = Ledger(ROOT / "data" / "evidence")
    raw_sources: dict[str, dict[str, Any]] = {}
    kev_path = DATA_ROOT / "known_exploited_vulnerabilities.json"
    size, digest = _download(KEV_URL, kev_path, force=True)
    kev_raw = kev_path.read_bytes()
    kev_evidence = ledger.store(content=kev_raw, tool="cisa_kev", command=["GET", KEV_URL], status="ok", summary="CISA Known Exploited Vulnerabilities public catalog snapshot", source_mode="imported")
    audit.append("public_intel_snapshot_loaded", "public-intel-updater", {"source": "CISA KEV", "url": KEV_URL, "evidence_id": kev_evidence.id, "sha256": kev_evidence.sha256})
    raw_sources["cisa_kev"] = {"url": KEV_URL, "path": str(kev_path.relative_to(ROOT)), "bytes": size, "sha256": digest, "evidence_id": kev_evidence.id}
    kev_dates = _load_kevs(kev_raw)

    current_epss_path = DATA_ROOT / "epss-current.csv.gz"
    size, digest = _download(EPSS_CURRENT_URL, current_epss_path, force=True)
    current_epss_raw = current_epss_path.read_bytes()
    epss_evidence = ledger.store(content=current_epss_raw, tool="first_epss", command=["GET", EPSS_CURRENT_URL], status="ok", summary="FIRST Exploit Prediction Scoring System current daily CSV snapshot", source_mode="imported")
    audit.append("public_intel_snapshot_loaded", "public-intel-updater", {"source": "FIRST EPSS", "url": EPSS_CURRENT_URL, "evidence_id": epss_evidence.id, "sha256": epss_evidence.sha256})
    raw_sources["first_epss_current"] = {"url": EPSS_CURRENT_URL, "path": str(current_epss_path.relative_to(ROOT)), "bytes": size, "sha256": digest, "evidence_id": epss_evidence.id}

    all_x: list[list[float]] = []
    all_y: list[int] = []
    all_w: list[float] = []
    all_dates: list[date] = []
    snapshot_stats: list[dict[str, Any]] = []
    for text_day in SNAPSHOT_DATES:
        snapshot = date.fromisoformat(text_day)
        epss_path = DATA_ROOT / "epss_history" / str(snapshot.year) / f"epss_scores-{text_day}.csv.gz"
        url = EPSS_RAW.format(year=snapshot.year, day=text_day)
        size, digest = _download(url, epss_path)
        raw_sources[f"epss_{text_day}"] = {"url": url, "path": str(epss_path.relative_to(ROOT)), "bytes": size, "sha256": digest}
        x, y, w, positives, negative_total = _read_epss(epss_path, snapshot, kev_dates)
        all_x.extend(x)
        all_y.extend(y)
        all_w.extend(w)
        all_dates.extend([snapshot] * len(y))
        snapshot_stats.append({"date": text_day, "positive": positives, "negative_population": negative_total, "sampled_rows": len(y)})
        print(f"loaded {text_day}: {positives} KEV additions in next {HORIZON_DAYS}d; {len(y) - positives} sampled negatives")

    train_rows = [i for i, snapshot in enumerate(all_dates) if snapshot <= TRAIN_CUTOFF]
    test_rows = [i for i, snapshot in enumerate(all_dates) if snapshot >= TEST_START]
    if not train_rows or not test_rows or len({all_y[i] for i in train_rows}) < 2 or len({all_y[i] for i in test_rows}) < 2:
        raise ValueError("not enough positive and negative samples for the documented time split")

    train_x = [all_x[i] for i in train_rows]
    train_y = [all_y[i] for i in train_rows]
    train_w = [all_w[i] for i in train_rows]
    test_x = [all_x[i] for i in test_rows]
    test_y = [all_y[i] for i in test_rows]
    test_w = [all_w[i] for i in test_rows]
    model = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_iter=120,
        max_leaf_nodes=15,
        l2_regularization=1.0,
        early_stopping=True,
        validation_fraction=0.15,
        n_iter_no_change=12,
        random_state=17,
    )
    model.fit(train_x, train_y, sample_weight=train_w)
    model_scores = [float(value) for value in model.predict_proba(test_x)[:, 1]]
    epss_scores = [row[0] for row in test_x]
    metrics = {
        "label": f"KEV catalog addition within {HORIZON_DAYS} days; not a ground-truth label for all exploitation",
        "feature_names": ["epss_probability", "epss_percentile", "cve_year", "cve_age_days"],
        "train_snapshot_dates": [SNAPSHOT_DATES[i] for i in range(len(SNAPSHOT_DATES)) if date.fromisoformat(SNAPSHOT_DATES[i]) <= TRAIN_CUTOFF],
        "test_snapshot_dates": [SNAPSHOT_DATES[i] for i in range(len(SNAPSHOT_DATES)) if date.fromisoformat(SNAPSHOT_DATES[i]) >= TEST_START],
        "gap_snapshot_dates": [SNAPSHOT_DATES[i] for i in range(len(SNAPSHOT_DATES)) if TRAIN_CUTOFF < date.fromisoformat(SNAPSHOT_DATES[i]) < TEST_START],
        "horizon_days": HORIZON_DAYS,
        "train_rows": len(train_rows),
        "train_positive_rows": sum(train_y),
        "test_rows_sampled": len(test_rows),
        "test_positive_rows": sum(test_y),
        "test_negative_population_weighted": sum(w for y, w in zip(test_y, test_w) if not y),
        "baseline_epss": _weighted_metrics(test_y, epss_scores, test_w),
        "trained_model": _weighted_metrics(test_y, model_scores, test_w),
        "model_iterations": int(model.n_iter_),
        "snapshot_stats": snapshot_stats,
        "data_sources": raw_sources,
        "training_data_captured_at": max(kev_evidence.captured_at, epss_evidence.captured_at).isoformat(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "The target is CISA KEV catalog addition, not all real-world exploitation.",
            "KEV absence is a weak negative because unlisted vulnerabilities may still be exploited.",
            "This model is an offline experiment and is not used by ProofPath risk ranking unless separately reviewed.",
        ],
    }
    model_path = DATA_ROOT / "proofpath_kev_forecast.joblib"
    joblib.dump(model, model_path)
    metrics_path = DATA_ROOT / "training_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    total_bytes = sum(int(source["bytes"]) for source in raw_sources.values())
    print(json.dumps({"downloaded_bytes": total_bytes, "model_path": str(model_path.relative_to(ROOT)), "metrics_path": str(metrics_path.relative_to(ROOT)), "metrics": metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
