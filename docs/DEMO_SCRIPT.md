# Day 4 demo rehearsal

This rehearsal uses only the synthetic fixture set and a local in-process HTTP server. It sends no traffic to public hosts or an engagement lab.

## Checklist

1. **Scope and denial:** run `python -m proofpath.cli redteam --scope scope.yaml`. Explain that the public address is a denied test case and no public packet is sent. The redteam suite uses fake resolution and local test servers.
2. **Import and evidence:** run `python -m proofpath.cli demo-load --scope scope.demo.yaml --data data/demo`. Point out the `SYNTHETIC / IMPORTED` label, evidence IDs, dropped out-of-scope records, correlation, and false-positive candidate. This is import data, not a live scan.
3. **Model plan:** show the candidate ID and code-built action in Plan. The model selects from the enum and supplies rationale; it cannot alter action fields. If Ollama is unavailable or its answer fails validation, the audited deterministic fallback is expected behavior. Latency still depends on model load, hardware, and token generation.
4. **Uncertainty and conflicts:** discuss the synthetic conflicting/closed-port evidence and risk factors. Missing CVSS is `not provided`; no score or finding is invented.
5. **Approval and replay:** `python scripts/verify_demo_e2e.py` performs an exact approved GET to a temporary loopback-only server, then attempts replay. Expected: first request HTTP 200; replay denied because approval is single-use.
6. **PDF and integrity:** the script writes `docs/sample_report.pdf`, verifies the clean audit/ledger, flips one byte in that PDF and one in an artifact, and demonstrates that verification names both. It restores the bytes after each check. Render with `pdftoppm -png -r 110 docs/sample_report.pdf docs/sample-report-page` and inspect the pages.
7. **Honest limits:** show `docs/INTEGRATION_MATRIX.md`. Nmap's WSL loopback was tested and returned a closed port. WSL access to host-only/Docker networks and real Nessus/Burp export variants remain unverified. Do not scan a lab until its authorized CIDR and exclusions are confirmed.

Run the end-to-end script only after a fresh `demo-load` into `data/demo`; it appends approval and report events and is intended as a single clean rehearsal per data directory. The report is synthetic and says so. Standards are described only as mappings when the source provides them.
