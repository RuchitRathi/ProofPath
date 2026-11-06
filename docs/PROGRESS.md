# Progress

## Current status

Day 1 path includes typed scope checks, signed decisions, Ubuntu WSL Nmap, recorded Nmap XML import, raw evidence with SHA-256, audit hash chaining, and artifact verification. Day 2 adds guarded Nessus and Burp XML importers, deterministic normalization/correlation, a schema-constrained Ollama proposer, and the Findings/Plan/Imports UI. Ubuntu WSL Nmap 7.98 and Qwen2.5 7B Q4_K_M are installed. The proposer returns a candidate ID and rationale only; ProofPath constructs and scope-checks the selected action. Day 3 Steps 1–7 and the Day 4 proof/documentation pass are complete. No public host was contacted.

Correction pass complete: Burp accepts only a narrowly validated internal ELEMENT/ATTLIST DTD with all entity and external identifier mechanisms rejected. Nessus and nmap continue rejecting every DOCTYPE. Current runtime settings select Ubuntu WSL for nmap and Qwen2.5 7B Q4_K_M for Ollama; the blank-tag fallback AppTest uses a temporary config selected through `PROOFPATH_OLLAMA_CONFIG`.

Day 2 scope is complete. Day 3 scope is complete through the rule-based skeptic. Step 7 began only after Steps 1–6 acceptance passed.

## Done

- 2026-11-03: Repository created at `C:\Users\RuchitRathi\Projects\proofpath`.
- 2026-11-03: Hard rules written to `.cursor/rules/proofpath.mdc` with `alwaysApply: true`.
- 2026-11-03: `docs/PROJECT.md` drafted from the brief and aligned to the code.
- 2026-11-03: Pydantic action, evidence, finding, hypothesis, approval, audit, and guard models.
- 2026-11-03: `scope.yaml` plus `scope_guard.py` with signed allow/deny decisions.
- 2026-11-03: Bypass checks for public addresses, exclusions, out-of-scope DNS, split DNS, argument injection, IPv6, `0.0.0.0`, and localhost. `proofpath redteam` runs those checks without sending packets.
- 2026-11-03: Hash-chained `audit.py` and `verify_chain`.
- 2026-11-03: Evidence ledger with `EV-0001` style IDs and SHA-256 verification.
- 2026-11-03: Nmap adapter: guarded argv list, XML parser, timeout, bad XML, and missing binary handling.
- 2026-11-03: Streamlit form in `app.py`.
- 2026-11-03: CLI commands `verify` and `redteam`.
- 2026-11-03: Pytest: 30 passed. Streamlit form checked with AppTest for `8.8.8.8` (denied, no evidence) and `10.10.1.5` (allowed, `tool_not_found` because nmap is not installed).
- 2026-11-03: Expanded Finding/EvidenceRef/Hypothesis schemas with reported severity, CVSS/CVE/CWE validation, assets, timestamps, confidence, status, and human validation state.
- 2026-11-03: Tightened scope edge cases, strict port integers, excluded hostname resolution, target variants, and added redteam cases.
- 2026-11-03: Added a separately labeled recorded nmap XML import path; imported ledger items carry `source_mode="imported"`.
- 2026-11-03: `proofpath verify` now checks audit links, all artifact hashes, and cited evidence IDs.
- 2026-11-03: Added observation XPath/excerpt provenance and tamper regression tests.
- 2026-11-03: Day 2 Step 1 — bounded safe NessusClientData_v2 parser, synthetic fixture, imported ledger evidence, per-item execution through `execute_action`, scope filtering with `out_of_scope` audit entries, and normalized findings with raw XPath excerpts. Numeric severity mapping follows the Nessus severity field; synthetic plugin ID/CVE values are placeholders.
- 2026-11-03: Day 2 Step 2 — bounded safe Burp issue XML parser, synthetic fixture, raw request/response storage without decoding, guarded finding emission, and out-of-scope audit.
- 2026-11-03: Day 2 Steps 3–4 — normalizer and deterministic correlator preserve sources/evidence, separate per-asset CVEs, record severity conflicts, and mark low-confidence findings contradicted by nmap closed ports as false-positive candidates.
- 2026-11-03: Day 2 Step 5 — rule-based HTTP/Burp candidates, local Ollama `/api/chat` with JSON Schema, evidence-cited rationale, one retry and audited fallback, and a non-executing scope gate. Model tag remains blank pending confirmation.
- 2026-11-03: Day 2 Step 6 — Assess/Findings/Plan/Imports UI, evidence excerpt display, analyst approve/skip controls, truthful integration matrix, and guarded default-off `skip_host_discovery`/`-Pn` argument.
- 2026-11-03: Correction Part A — Burp-only internal DTD allowlist accepts ELEMENT/ATTLIST declarations after safe-subset validation, strips the DTD before parsing, and rejects entity declarations/references and SYSTEM/PUBLIC identifiers. Added synthetic DTD fixture and XXE/entity rejection tests. Request/response base64 content remains raw and excerpts capped.
- 2026-11-03: Correction Parts B–E — verified import scope checks and counts, proposer candidate/ledger/action invariants and duplicate skip reason, bounded prompt fields, injected plugin_output exclusion, correlation confidence and seeded evidence preservation, UI upload summaries/failure handling, and an Ollama checker that reports reachability, tags, configured-tag presence, and schema-call validity. Real Burp/Nessus variants and live model/nmap behavior remain unverified.
- 2026-11-03: Final correction acceptance — `python -m pytest -q`: 115 passed in 7.23s; redteam: 52 passed, 0 failed. Disposable synthetic Nessus import verification passed; after flipping its artifact byte, verification failed naming `EV-0001`. `scripts/check_ollama.py` exited 0 with a blank tag and skipped its model call because local API access was blocked by the sandbox. Ollama reported both requested tag deletions; a follow-up tag-list query could not be approved.
- 2026-11-03: AppTest confirms a conflicted finding displays both source names and its recorded severity conflict note.
- 2026-11-05: Added validated `nmap.yaml` WSL runtime settings, configured the fixed Ubuntu `wsl.exe --exec nmap` argv prefix, and confirmed Nmap 7.98 in Ubuntu. Focused nmap, app, and docs tests passed: 28 passed. Qwen2.5 7B Q4_K_M model download is underway.
- 2026-11-06: Day 3 Steps 1–6 acceptance before Step 7: `python -m pytest -q` — 129 passed. `proofpath redteam` — 69 passed, 0 failed. Approval tests used only an in-process loopback server; no public or lab host was contacted.
- 2026-11-06: Day 3 Step 7 — rule-based skeptic emits evidence-linked hypotheses and proposes a guarded one-port Nmap recheck. It never runs the scan; only a matching closed-port observation with evidence ID and locator can mark a finding refuted.
- 2026-11-06: Final Day 3 acceptance after Step 7, imported/live exposure separation, and IPv6 port-grounding correction: `python -m pytest -q` — 133 passed in 15.39s; `proofpath redteam` — 69 passed, 0 failed. Focused grounding/risk checks — 3 passed. No external host was contacted. Ollama download is still in progress.
- 2026-11-06: Proposer correction — model schema selects from candidate-ID enum only; code builds the exact candidate action. Added relevant-evidence citation validation, one retry then audited deterministic fallback, Plan-tab code-generated exposure/evidence/risk facts, and plugin_output injection regression. Real Qwen batches (10 each): live exposure 10/10 JSON, 2 fallback, 11.560s average; imported exposure 10/10, 1 fallback, 9.574s; no web port: no candidates/model calls. Exact built-action match was 10/10 in both candidate cases. Live/imported top score changed 80.0 to 74.0; candidate ID remained C1.
- 2026-11-06: Final proposer regression: `python -m pytest -q` — 130 passed in 11.40s; `proofpath redteam --scope scope.yaml` — 69 passed, 0 failed. Real model injection prompt omitted hostile Nessus plugin_output; selected C1, built the fixed scoped import_burp action, and scope guard allowed it.
- 2026-11-06: Day 4 baseline committed and tagged `day3-done` (initial repository had no commits); `.gitignore` excludes pytest temp folders and samples_real. Added separate `scope.demo.yaml`, three SYNTHETIC fixtures, and guarded `demo-load`. Acceptance: 130 passed; demo-load reports 6 findings, 4 proposer candidates, one excluded Nessus and one excluded Burp item dropped, and a low-confidence closed-port false-positive candidate. Proposer selected C1 with deterministic fallback in the recorded run; model response was valid only after its fallback path.
- 2026-11-06: WSL Nmap argv now explicitly selects TCP connect mode with `-sT`; focused/full pytest passed before commit. Live loopback scan verification remains pending.
- 2026-11-06: Loopback WSL scan emitted Nmap's standard inert `<!DOCTYPE nmaprun>`, which the parser rejected. Parser now permits only that exact Nmap declaration; entity subsets/external identifiers remain rejected. Focused Nmap tests: 17 passed. Scan parsed one closed-port observation from WSL's separate loopback namespace; raw artifact strict UTF-8 and LF line endings verified, SHA-256 matched metadata. Windows in-process server was not reachable at WSL 127.0.0.1.
- 2026-11-06: End-to-end synthetic/imported demo: approved local GET returned HTTP 200; replay denied; verify passed on a fresh run; tampered PDF named the report path and tampered artifact named EV-0001. PDF text inspection found source labeling said imported but not synthetic; changed report labeling to detect `SYNTHETIC` in raw ledger bytes and summary, with a regression assertion. The first test regeneration reused an old audit/report path and correctly failed because the report hash no longer matched; rerunning from clean disposable data is required.
- 2026-11-07: Five-run direct-Qwen vs ProofPath synthetic scorecard saved in `docs/SCORECARD.md`; baseline was faster and equally clean on mechanically detected fabrication but often omitted claims. ProofPath returned all 6 findings each run and selected C1, with 2/5 safe fallbacks. Audit reasons included unrelated/uncited evidence and Ollama timeouts.
- 2026-11-07: Fallback correction based on audit: timeout raised 30s to 60s; Streamlit warms configured Qwen once per session; prompt now asks for one evidence ID from the selected candidate. Focused proposer/UI tests: 23 passed. Real warm-up passed. Repeated five-run scorecard: 0/5 fallbacks (two first attempts were rejected/retried: one timeout, one absent evidence ID), valid JSON 5/5, action candidate exact, mean 15.570s. The baseline remained faster at 2.300s and usually omitted extractable facts.
- 2026-11-07: `samples_real/` is absent, so no real Nessus/Burp files were parsed. Integration matrix now states Burp DTD behavior accurately and describes the limited WSL loopback scan result.
- 2026-11-07: Day 4 docs added: Windows setup, architecture, tool matrix, and a rehearsable synthetic demo. The sample PDF was regenerated from a clean disposable ledger and rendered to seven images for inspection; chart is legible, tables wrap without clipping, synthetic/imported labels are present, and prohibited compliance wording is absent. PDF SHA-256: `b0ace0a890078b8ec3d5bebee4a368b10598503db6a90792cc11cdabeb70ab18`.
- 2026-11-07: Clean synthetic E2E: guarded imports -> findings/risk/proposer -> exact approved loopback GET (HTTP 200) -> replay denied -> PDF -> verify passed. Tampered PDF verification named `docs/sample_report.pdf`; tampered artifact verification named `EV-0001`. The sandbox blocked the first local-server attempt; elevated rerun passed. Host-only/Docker WSL routing remains unverified.
- 2026-11-07: Final full pytest: 132 passed in 16.79s; final redteam: 69 passed, 0 failed. Both ran elevated because sandbox restrictions blocked loopback sockets/temp access. The initial sandboxed pytest run had four environment/docs failures; the compliance wording in demo docs was removed and the elevated final run passed.

## Next up

### Blocked on me

- Confirm Ubuntu WSL remains the intended Nmap distribution for the live runtime.
- Confirm the authorized lab CIDR and exclusions.
- Provide real Nessus and Burp exports so parser variants can be checked against actual files.

### Future work (outside completed Day 4 scope)

- Verify host-only and Docker lab routing only after an authorized lab target is supplied.
- Validate parser variants against actual Nessus and Burp exports.
- Any future ZAP work requires a separate scoped implementation and review; it was not added in Day 4.

## Decision log

- 2026-11-03: One choke point, `execute_action`, always calls `scope_guard.check` before an adapter. Adapters also require a signed allow so a forged decision cannot start nmap.
- 2026-11-03: Decisions are HMAC-signed in process memory. The audit chain is a separate control.
- 2026-11-03: Hostnames are resolved during the check. Nmap is given canonical IPs only. If any resolved address is out of scope, the whole action is denied.
- 2026-11-03: Nmap does not receive NSE scripts, a shell string, or the analyst's free-text request.
- 2026-11-03: `active_validate` is hard-denied until an approval state machine exists. **Superseded 2026-11-06:** exact-action independent human approval, expiry, and single-use enforcement were implemented; listing alone still does not enable it.
- 2026-11-06: The proposer model selects by an enum-constrained candidate ID and supplies rationale only. ProofPath builds the Action from the selected candidate; raw model action fields are not accepted. Invalid output/citations retry once, then audited top-rule fallback.
- 2026-11-06: `active_validate` is enabled only with a valid exact-action approval; all host, exclusion, port, and allowlisted-path checks remain mandatory, and each approval is single-use.
- 2026-11-03: Tools without a working executor are Planned or Unsupported, not Live and not Import-only.
- 2026-11-03: CVSS display for null is the text `not provided`.
- 2026-11-03: Loopback, unspecified, multicast, and link-local addresses are denied by type. Loopback can be turned on with `allow_loopback` plus an explicit CIDR.
- 2026-11-03: IPv4 scopes shorter than /8 and IPv6 scopes shorter than /32 are rejected so a default route cannot be loaded by mistake.
- 2026-11-03: Timeout bytes are stored and are not parsed into services. Output over 8,000,000 bytes is not stored.
- 2026-11-03: The shipped nmap fixture is synthetic parser input, not a claimed client scan.
- 2026-11-03: ReportLab selected for future PDF work due to WeasyPrint's Windows GTK dependency risk.
- 2026-11-03: Recorded nmap XML is an import-only action, always labeled imported in the ledger and interface.
- 2026-11-03: Excluded hostnames resolve at policy load; an unresolved exclusion is a clear policy error.

## Known issues/bugs

- The default allow range `10.10.0.0/16` is a placeholder lab, not confirmation that this network is the engagement.
- Ubuntu WSL Nmap 7.98 is installed and configured with `-sT`; a WSL loopback scan returned a closed port. Host-only and Docker lab routing remain unverified. Confirm the lab CIDR and exclusions before scanning.
- The HMAC key changes when the Streamlit process reloads. That does not weaken the on-disk audit chain.
- The Nessus fixture is synthetic and plugin ID/CVE placeholders are not authoritative; verify exact details against a real Nessus export. The Burp fixtures are synthetic; exact current export variants need a real sample.

## Test status

2026-11-07: After Qwen timeout/prompt correction, five-run synthetic comparison: `python scripts/baseline_vs_proofpath.py`; direct baseline valid JSON 5/5, 0 fabricated claims, 2.300s mean; ProofPath 5/5, 0 fabricated claims, 6/6 findings each run, 0/5 final fallbacks, 15.570s mean, C1 each run. Two first responses were rejected and successfully retried (one timeout, one invalid evidence ID). This is a small synthetic comparison, not a general quality benchmark. Earlier 10-run proposer-correction measurements remain recorded above.
- 2026-11-07: Model warm-up request passed. `ollama.yaml` selects `qwen2.5:7b-instruct-q4_K_M`, request timeout is 60 seconds, and Streamlit warms the model once per session. Local execution removes hosted network delay but does not guarantee low token-generation latency; hardware-specific CPU/GPU utilization was not measured.
- 2026-11-07: Final Day 4 acceptance: `python -m pytest -q` — 132 passed in 16.79s; `python -m proofpath.cli redteam --scope scope.yaml` — 69 passed, 0 failed. Clean synthetic E2E approval/execute/replay, PDF generation, and `proofpath verify` passed; tamper checks named the report path and EV-0001. WSL lab network access and real Nessus/Burp export variants remain unverified.

