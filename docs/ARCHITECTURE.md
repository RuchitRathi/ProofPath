# Architecture

## Components

- **Streamlit UI (`app.py`)** collects analyst requests and displays scope decisions, observations, findings, plans, approvals, and reports.
- **Typed schemas (`schemas.py`)** define Action, GuardDecision, Evidence, Finding, Hypothesis, and ApprovalRequest.
- **Orchestration (`adapters/base.py`)** calls `scope_guard.check(action)`, audits the decision, and dispatches only an allowed action to its adapter.
- **Adapters** run WSL Nmap, import Nmap/Nessus/Burp XML, or perform the narrowly approved HTTP validation. XML parsers preserve provenance and refuse unsafe entity mechanisms.
- **Ledger and audit (`ledger.py`, `audit.py`)** store raw artifact bytes, SHA-256, evidence IDs, and a previous-entry hash for every audit event.
- **Analysis** normalizes and correlates findings, computes deterministic risk factors, and generates skeptic hypotheses. Ollama can select a rule candidate by ID and provide rationale; code constructs the Action.
- **Report generator (`report/generator.py`)** creates a PDF, checks finding references, and audits the report hash and evidence links.
- **CLI (`cli.py`)** exposes `redteam`, `demo-load`, and `verify`.

## Data flow

```text
analyst request
    -> typed Action
    -> scope_guard.check(Action)
    -> allow: adapter -> raw bytes -> evidence ledger -> audit event
    -> parsed observations/findings -> correlation and deterministic risk
    -> optional Ollama candidate-ID selection -> code-built Action -> guard check
    -> exact approval state machine for active validation
    -> PDF + report hash + proofpath verify
```

All model input is bounded parsed data. Raw plugin output and request/response bodies are excluded from the proposer prompt. The model cannot set target, ports, tool, arguments, engagement, or requester. All adapters require a valid signed allow decision before execution. The model does not grant authorization.

## State and boundaries

The evidence ledger and hash-chained audit log are filesystem state under the configured data directory. Scope policy is operator-controlled. Guard HMAC keys and approval tokens are process-local; a process restart invalidates them. Ollama is an optional local service. Nmap runs in the configured Ubuntu WSL distribution. WSL network reachability to host-only and Docker lab networks depends on the workstation network configuration and is not inferred from a loopback scan.

See [PROJECT.md](PROJECT.md) for schemas, threat model, and detailed behavior.
