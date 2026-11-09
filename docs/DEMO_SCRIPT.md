# Demo Script — ProofPath (hackathon submission, PS-1)

Rehearsal steps and honest limitations for the live judging session. Everything
below runs on one Windows workstation with Ubuntu WSL (Nmap) and a local Ollama
service. Nothing uses a hosted model API. Times are omitted on purpose; run the
pre-flight once before the session.

## 0. Pre-flight

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

# External tools (installed separately)
wsl --distribution Ubuntu --exec nmap --version
ollama list

# Green safety + regression gates
python -m pytest -q
python -m proofpath.cli redteam --scope scope.yaml
```

Expected: `177 passed` and `redteam — 69 passed, 0 failed`.

Confirm the authorization boundary in `scope.yaml` before any live action. The
checked-in file is a **placeholder** (RFC1918 CIDRs, `10.10.0.1` excluded). The
UI cannot widen it; only the engagement lead edits the file.

## 1. Judges' checklist walkthrough (PS §10)

### 1 — Authorized target + request, and scope validation
Start the console: `python -m streamlit run app.py`.

- Type an out-of-scope target such as `8.8.8.8` into **Scan & Recon → Target**,
  then **Run Reconnaissance**. The guard **denies** it (public IP, not in any
  authorized CIDR) and the decision is written to the audit chain.
- Type an in-scope target such as `10.20.0.10` and a request like
  *"Enumerate services and flag web weaknesses."* The guard **allows** it.
- CLI equivalent: `python -m proofpath.cli scan --target 10.20.0.10 --ports 80,443`

Key point for judges: a request typed in the UI is **not** authorization; the
scope guard is the only control that decides.

### 2 — AI assessment plan with tool selections and reasoning
In **AI Planner**, click **Generate plan with Qwen AI**. The panel separates
`⬡ Code generated` (rule facts, evidence IDs, exposure state) from
`✦ AI rationale (model output)`. If Ollama is offline, the deterministic rule
planner takes over and the UI says so.

### 3 — Multi-tool execution / import
Load the labeled synthetic dataset. In the UI click **Load Full 7-Tool
Assessment** in the sidebar (explicit, user-triggered — nothing auto-runs on
startup). CLI equivalent:

```powershell
python -m proofpath.cli demo-load --all-tools --scope scope.demo.yaml --data data/demo
python -m proofpath.cli tools
```

Each import passes through the same guarded `execute_action` path and creates an
`EV-####` ledger artifact with a SHA-256 hash.

### 4 — Normalization, correlation, dedup, false-positive handling
Open **Findings**. The same issue reported by two tools is correlated into one
finding with `source_tools = [..]`, and conflicting severities are surfaced as a
`false_positive_candidate` / conflict note rather than silently dropped.

### 5 — Risk prioritization + human-approval checkpoint
Open **Risk Rank** for the multi-factor ordering and the severity distribution.
Open **Approvals** to see the human gate: a proposed active check must be
independently approved before it runs, and the approval is single-use.

### 6 — Download the report and trace a finding to evidence
Open **Report**, click **Generate PDF report**, and download it. In the PDF,
pick a finding in section 7.4 and trace its `EV-####` reference to Appendix A
(evidence index + SHA-256) and to the raw artifact in the ledger.

### 7 — Safe failure handling and integration honesty
- With WSL/Nmap absent, a live scan records a truthful
  `tool_not_found` status — no finding is invented.
- Attempting an unsupported tool (for example SQLMap) is refused; Appendix B of
  the report lists every integration as `live` or `import-only`, with no
  overstated coverage.

## 2. Human-approval + audit trace (offline, deterministic)

```powershell
# End-to-end: guarded imports -> grounded proposal -> exact single-use approval
# -> execute once -> replay denied -> PDF -> verify
python -m proofpath.cli verify --audit data/audit.jsonl --ledger data/evidence
```

The replay attempt is denied because the approval is bound to one exact action
hash. Tampering with a stored artifact or the PDF makes `verify` fail and name
the affected evidence ID.

## 3. Known limitations (state these plainly to judges)

- **Live capability is Nmap only.** The six other tools are **import-only**;
  ProofPath consumes their exported reports and never drives them live.
- **Live Nmap was verified only against WSL loopback.** Host-only and Docker lab
  routing are unverified.
- **No real vendor exports were available.** Nessus, Burp, OpenVAS, Nikto, ZAP,
  and Metasploit demos use synthetic fixtures that follow each tool's schema.
- **Model proposals need local Ollama.** When it is unavailable the rule planner
  answers and the UI labels the result as a fallback; no model output is
  fabricated.
- **`scope.yaml` is a placeholder.** Replace it with an engagement scope you are
  authorized to assess before any live run.
- **External components are separately licensed.** Review Nmap, Ollama, and the
  scanned-tool licenses yourself.
