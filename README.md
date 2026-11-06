# ProofPath

ProofPath is a local, auditable assistant for authorized security assessments. It keeps scope decisions, tool output, findings, model inference, approvals, and reports reviewable. The model proposes a candidate by ID; deterministic code builds the action and the scope guard decides whether it can run.

## Setup (Windows)

Requires Python 3.11+, Windows with Ubuntu WSL for the configured Nmap adapter, and a local Ollama service for model proposals. The checked-in configuration currently selects `qwen2.5:7b-instruct-q4_K_M` at `http://127.0.0.1:11434` with a 60-second request timeout. A local model can still take seconds: the first request loads weights, and token generation speed depends on hardware and prompt/response size. ProofPath warms the model once per Streamlit session; this reduces cold-start delay but does not make inference instantaneous.

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Install Ubuntu WSL and Nmap separately, then confirm with `wsl --distribution Ubuntu --exec nmap --version`. Install Ollama and the configured tag separately; confirm with `ollama list` and `python scripts/check_ollama.py`. These workstation checks passed during the 2026-11-07 Day 4 pass. WSL was verified only against its own loopback; host-only and Docker lab routing remain unverified. No real Nessus or Burp exports were available.

## Run

```powershell
python -m streamlit run app.py
python -m pytest -q
python -m proofpath.cli redteam --scope scope.yaml
python -m proofpath.cli demo-load --scope scope.demo.yaml --data data/demo
python -m proofpath.cli verify --audit data\demo\audit.jsonl --ledger data\demo\evidence
```

The demo dataset is explicitly synthetic. It exercises the same guarded import paths and does not scan a host. `scope.yaml` is a placeholder policy; replace it only with an engagement scope you are authorized to assess. Review exclusions and allowed ports before any live run. Do not treat a UI request as authorization.

`docs/sample_report.pdf` is a generated synthetic report. `docs/DEMO_SCRIPT.md` contains the rehearsal steps and limitations. `docs/INTEGRATION_MATRIX.md` is the current tool status reference. `docs/SCORECARD.md` records measured synthetic model comparisons and their limits.

## Dependencies and assumptions

Runtime dependencies: Pydantic, PyYAML, Streamlit, and ReportLab. Development extras: pytest and pypdf. Nmap and Ollama are external local services/tools, not Python dependencies. Install versions from their respective official distributions and review their licenses. ProofPath uses no hosted model API. PDF generation uses ReportLab; parser and application behavior is covered by the repository test suite.

## Safety and audit

Every tool call goes through `execute_action` and `scope_guard.check` with a typed Action. Commands use argument lists, never `shell=True`. Active HTTP validation needs an exact, independent, single-use approval. Evidence is stored as bytes with SHA-256 and referenced by findings. Audit entries are hash chained. Use `proofpath verify` after report generation or evidence transfer. See [the project spec](docs/PROJECT.md) for details.
