# ProofPath

ProofPath is an auditable assistant for an authorized security assessment. The analyst states a request. Deterministic code checks scope, runs a tool, stores the raw output, and writes a hash-chained audit entry. A later model may select a prebuilt next step and explain the choice. It does not construct actions, decide whether a tool may run, or invent evidence.

This document is the living spec. `docs/PROGRESS.md` is the running log. Integration status below describes this build, not the intended end state.

## 1. Problem and goals

Authorized vulnerability assessment and penetration testing (VAPT) produces a client report. The work moves from reconnaissance to findings, and the findings need evidence a reviewer can check.

The hackathon ask is a conversational agent that can walk that path and emit a client-ready PDF. Judges score reasoning, end-to-end coverage, technical accuracy, correlation and false positives, risk prioritization, safety and scope control, report quality, and efficiency.

ProofPath's position: other agents ask you to trust the model. ProofPath lets you verify it.

ProofPath implements full end-to-end coverage across the 8 VAPT lifecycle stages: Analyst Request, Agent Planning, Scan Orchestration, Result Ingestion, AI Analysis, Risk Prioritization, Human Review, and Unified VAPT Report.

All 7 named tools from the problem statement have dedicated adapters: live and imported Nmap, plus bounded, secure report importers for Nessus, Burp Suite, OpenVAS/Greenbone, Nikto, OWASP ZAP, and Metasploit. An interactive Conversational Security Assistant guides analysts through scope validation, tool selection, risk triage, and next steps. An Autonomous VAPT Agent (`src/proofpath/agent.py`) implements a ReAct-style planning, execution, and reflection loop powered by local Qwen and PydanticAI, orchestrating multi-step assessments within strict scope guard boundaries. Results are normalized into typed, evidence-backed findings and correlated deterministically. Active validation is strictly gated by independent human approval and scope authorization. Deliverables include deterministic ReportLab PDF reports, OASIS SARIF v2.1.0 exports, and retesting change comparison diffs.

## 2. Personas

- Analyst: types a request and a target, reads the scope decision, and reviews evidence IDs before accepting a finding.
- Engagement lead: edits `scope.yaml`. That file is the default authorization boundary, containing RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or configurable custom CIDRs. In the console, the analyst may optionally toggle "Permit All Target IPs (Open Scope Mode)" for engagements targeting arbitrary external/lab addresses.
- Client: reads the eventual report. Every finding they see must cite evidence. Scores that were not supplied by a tool are shown as "not provided".

## 3. Judging criteria and how each is addressed

| Criterion | Weight | How this build addresses it |
| --- | --- | --- |
| AI reasoning | 20 | Local Qwen selects among distinct evidence-backed next steps across all 7 tools: a one-port live recheck for imported exposure, web coverage (Burp/Nikto/ZAP) when web ports are open, infrastructure coverage (Nessus/OpenVAS) when host results are missing, or controlled Metasploit verification for high-severity findings. It receives exposure provenance, evidence IDs, matching risk score/factors, the rule reason, and expected result. It returns a candidate ID and grounded rationale only; code supplies observed facts beside the AI inference, builds the exact action, and sends it through the scope guard. The reasoning workflow is implemented; the judges' score is not verifiable here. |
| End-to-end coverage | 15 | Scan/import paths, evidence-backed findings, deterministic correlation, approval-gated validation, risk ranking, PDF generation, and audit entries work; all workflow tabs are present. |
| Technical accuracy | 15 | Port rows come from nmap XML attributes. Missing attributes stay null. NSE `script` elements are ignored. |
| Correlation and false positives | 15 | Deterministic correlation merges exact asset/port/CVE matches, retains evidence, and records conflicts; closed-port contradictions can become false-positive candidates or evidence-backed skeptic refutations. |
| Risk prioritization | 10 | `risk.py` ranks by documented finding factors plus verified NVD CVSS context, FIRST EPSS probability, and positive CISA KEV listing evidence. The separately trained KEV-addition experiment is not yet used in product scores. Unknown evidence factors are excluded and weights are renormalized. |
| Safety and scope control | 10 | `scope_guard.check` is the only authorization decision. Active validation requires exact independent human approval. Redteam includes a loopback-only local HTTP server and sends no external traffic. |
| Report quality | 10 | ReportLab creates a deterministic PDF with ordered sections, severity chart, evidence index, integration matrix, and audited report/evidence hashes. |
| Efficiency and robustness | 5 | Adapters use argument lists, timeouts, a capture cap, and pytest around the guard, the chain, and the parser. |

## 4. Architecture and data flow

```
analyst text in Streamlit
  -> app.py builds an Action (Python, not a model)
  -> audit event analyst_request
  -> execute_action()
       -> scope_guard.check(action) -> signed GuardDecision
       -> audit event scope_decision
       -> if denied: stop
       -> NmapAdapter.run uses resolved IPs and normalized arguments only
       -> `wsl.exe --distribution Ubuntu --exec nmap ...` argument list, shell is false
       -> ledger stores stdout bytes, SHA-256, id EV-0001...
       -> XML parser emits ServiceObservation rows that cite that id
       -> audit event nmap_result (id and hash, not the XML)
  -> UI shows allowed/denied, status, evidence id, observed ports
  -> skeptic creates evidence-linked hypotheses and proposes a guarded one-port recheck; it does not execute the proposal
  -> human request and independent approval bind one GET/HEAD to one finding, target, port, and allowlisted path
  -> execute_action -> scope_guard.check(action, approval) -> HTTP adapter (no body/headers/redirects) -> live response evidence -> audit outcome
  -> deterministic ReportLab PDF -> evidence IDs resolve to ledger artifacts and report SHA-256 is audited
```

Tool output is stored as bytes and displayed as parsed fields. The optional proposer receives only the bounded parsed-field summary inside an untrusted-data block; raw artifacts, plugin output, and request/response bodies are excluded.

A signed decision carries an HMAC. The key lives on the `ScopeGuard` instance. Flipping `allowed` after `check` fails `verify_decision`, and an adapter will not start. `active_validate` also needs an approved, unexpired, unused `ApprovalRequest` whose hash matches its exact target/port/method/path/finding binding.

Nessus, Burp, OpenVAS, Nikto, OWASP ZAP, and Metasploit report import functions are available programmatically and in the Streamlit Imports tab. The disposable WSL local lab scans only WSL loopback at `127.0.0.1:8080`; it does not verify host-only or Docker lab routing.

The optional proposer selects a stable candidate ID from the current rule-generated candidate set. For each effective open web endpoint, imported exposure can produce a one-port Nmap TCP-connect recheck; missing Burp, Nikto, or ZAP web coverage produces the matching import candidate; missing Nessus or OpenVAS infrastructure coverage produces host-level import candidates; and high-severity or exploitable findings produce controlled Metasploit validation candidates. The latest live observation supersedes imported evidence for that endpoint, including a live closed result. Already-covered sources and action types disabled by scope settings are omitted. Candidates carry their related finding IDs, risk score and included factors, exposure source and evidence ID, rule reason, an action-specific rationale requirement, and expected result. Ollama receives those facts plus a JSON schema whose candidate_id is an enum of the current IDs and returns only candidate_id plus rationale (observed, inferred, why). ProofPath constructs the Action from that candidate; model output cannot supply or alter target, ports, tool, arguments, engagement, or requester. Each observed rationale claim must state a fact in words and cite exactly one candidate-relevant ledger evidence ID; citations in the rest of the rationale must also resolve to that candidate. The proposer rejects rationale that labels imported exposure as live-observed, refers to another candidate, or fails to explain the selected action type. Invalid JSON, an out-of-set ID, or invalid evidence is retried once, then the top rule-ranked candidate is selected and audited. If the model client is unavailable before a request, the top rule-ranked candidate is selected directly and audited. The built Action still passes through `scope_guard.check`. Proposal approval queues the action; the separate Nmap run button performs only the selected one-port TCP-connect action through the same choke point. Tool import candidates require an analyst-supplied export in Imports; they do not launch those scanners. Ollama requests keep the model loaded for 30 minutes and cap output at 96 tokens; audited response metrics separate model load, prompt evaluation, token generation, and total duration.

The Plan tab shows the candidate action types and expected results, then puts code-generated observed facts (exposure state, evidence IDs, matching risk score, and included score factors) beside the model rationale labeled **AI inference**. The decision trace explains whether the selected step is a one-port Nmap recheck, a Burp/Nikto/ZAP web import, an OpenVAS/Nessus host import, or a controlled Metasploit validation import. Only the Nmap action has a separate explicit run button; every execution passes through the regular scope guard. If Ollama is unavailable, the UI queues the top deterministic rule candidate. The model's inference remains separately labeled and grounded. The Assistant tab provides conversational natural-language assessment guidance, target scope validation, and stage-by-stage tool recommendations. The Agent tab hosts the autonomous ReAct orchestrator (`VAPTAgent`), allowing analysts to launch multi-step autonomous investigations with live ReAct trace visualization, plan generation, and pending import queues.

## 5. Schemas

Implemented in `src/proofpath/schemas.py`. All records use `extra="forbid"`.

### ActionName and Action

`nmap_scan`, `import_nmap_xml`, `nikto_scan`, `zap_scan`, planned imports, approvals, active validation, and report generation are typed action names. `Action` includes `id`, `name`, `target`, strict integer `ports`, `arguments`, `engagement_id`, and `requested_by`.

### Evidence and EvidenceRef

`Evidence` preserves `id`, `tool`, `command`, `sha256`, `captured_at` (UTC), `artifact_path`, `status`, `summary`, and `source_mode` (`live` or `imported`). `EvidenceRef` has `evidence_id`, `locator` (XPath/line/JSON path), and `excerpt` copied verbatim and capped at 300 characters.

### Finding

A finding contains `id`, `title`, `asset` (`ip`, optional `hostname`), `port`, `protocol`, `service`, `source_tools`, one or more `evidence` references, `observed`, and `inference` (AI-written and explicitly labeled). It also preserves reported `severity` (`critical`, `high`, `medium`, `low`, `info`, `not_provided`), `cvss`, `cvss_vector`, `cves`, `cwes`, `mapped_to`, optional tool-reported `exploit_available`, `confidence` (`low`, `medium`, `high`), `status` (`confirmed`, `suspected`, `false_positive_candidate`, `refuted`), UTC `first_seen`/`last_seen`, `validation_status` (`not_validated`, `validated_approved`, `rejected_by_human`), and `conflict_notes`. CVE and CWE identifiers are regex-validated. The Nessus importer creates tool-backed findings; nmap banners alone do not.

### Hypothesis

`id`, `statement`, `evidence_for`, `evidence_against`, and `status` (`open`, `supported`, `refuted`). Both evidence lists contain `EvidenceRef` values. `skeptic.py` proposes a one-port nmap recheck through `execute_action` and the scope guard; it cannot execute the scan. A finding becomes `refuted` only when a matching closed-port observation with evidence ID and locator is recorded, and that reference is added to the finding.

### Normalization and correlation

`normalizer.py` maps Nessus and Burp reported fields into `Finding`; it retains UTC import-capture timestamps and does not synthesize absent CVSS/CVE/severity. Nmap remains a service observation source and never creates a vulnerability finding from a banner. Correlation deduplicates on `(asset IP, port, protocol, CVE)` when CVE exists, otherwise normalized CWE or title. IP and port are part of every key, so one CVE on two hosts remains two findings. A duplicate from two independent reporting tools with no conflict becomes high confidence/confirmed. A single source retains its reported confidence mapping (Nessus is low because its mapping supplies no confidence; Burp confidence is mapped from the export). Severity, score/vector, or service disagreements retain one finding with `suspected`, a source-attributed conflict note, and conflicting scalar severity/score set to `not_provided`/null. A low-confidence single-tool finding contradicted by an nmap `closed` observation becomes `false_positive_candidate`; the nmap observation is also added as an evidence reference. All evidence references are retained.

| Condition after correlation | Confidence | Status |
| --- | --- | --- |
| Two or more independent reporting sources, no scalar conflict | high | confirmed |
| One reporting source, no contradiction | Retain that source's confidence | Retain that source's status |
| Sources disagree on severity, CVSS, vector, or service | Lower of the source confidences | suspected |
| Low-confidence, single-source finding contradicted by nmap `closed` | low | false_positive_candidate |
| Other nmap `closed` contradiction | Retain existing confidence | suspected |

### Other records

`GuardDecision` carries the signed scope decision. `ServiceObservation` includes evidence ID, XPath locator, source excerpt, and `source_mode` (`live` or `imported`). Imported open ports do not establish live exposure in risk ranking. `ApprovalRequest` stores a hash of its exact target, single port, method, path, and finding ID, plus requester/approver, expiry, a process-bound decision token, and single-use consumption state. `format_cvss(None)` displays `not provided`.

### Risk scoring

`risk.py` uses reported severity (16%), reported CVSS (16%), observed exposure (12%), tool-reported exploit availability (12%), analyst-set asset criticality (12%), correlator confidence (12%), NVD CVSS context (8%), FIRST EPSS probability (8%), and CISA KEV listing (4%). Without public context, the first six factors retain their previous relative weights after renormalization. Factor values are mapped to 0–10: critical/high/medium/low/info = 10/8/6/3/1; CVSS keeps its reported 0–10 value; a live open nmap observation = 10; Nessus exploit availability true/false = 10/0; low/medium/high criticality = 2/5/10; low/medium/high confidence = 3/6/9. The NVD CVSS context is used only when the finding has no scanner-reported CVSS and never overwrites that field. EPSS probability is mapped to 0–10; KEV listing contributes a positive factor only when listed, while absence is excluded rather than treated as proof of no exploitation. The medium criticality default and correlator confidence are explicit inputs. Exposure is `unknown` without a matching live open observation; imported-only observations do not establish live exposure. Missing values are `not provided` or `unknown`, excluded, and the included weights are renormalized. The score is the weighted mean × 10 on a 0–100 scale. Only confirmed/suspected findings share the top status tier; false-positive candidates and refuted findings follow in that order, independent of numeric score. Each factor exposes its source and configured weight.

The Risk tab can load a cached public snapshot only after its file SHA-256 and ledger evidence verify. `scripts/train_public_risk_model.py` downloads dated FIRST EPSS snapshots plus the current FIRST EPSS and CISA KEV feeds into the ignored project-local `data/threat_intel/training/` directory. It trains an offline experiment to estimate later CISA KEV catalog addition within 90 days from EPSS and CVE-age features; it is not a detector, does not fine-tune Qwen, and is not used in product ranking because the proxy label and evaluation do not establish real-world detection quality. Install its optional dependencies with `python -m pip install -e ".[training]"`, then run `python -B scripts/train_public_risk_model.py`. `scripts/fetch_nvd_context.py --findings <findings.json>` fetches NVD CVE metadata for CVE IDs found in a local findings export; this is read-only public metadata, not a host scan. Current public context can be reloaded in the Risk tab. EPSS is a 30-day global exploitation probability, not an environment-specific risk score; CISA KEV inclusion is positive catalog evidence, and non-inclusion is not evidence that exploitation did not occur.
## 6. Hard rules

1. Every tool execution goes through `scope_guard.check(action)` inside `execute_action`. The guard accepts a typed `Action`.
2. Processes are started with argument lists. `shell=True` is not used. Nmap flags are chosen by `build_argv`, not by free text.
3. The model may only emit a candidate ID and rationale from the constrained proposer schema; code builds the typed `Action`. Tool bytes stay in the ledger. The UI renders parsed fields as a table.
4. The parser does not create CVEs, CVSS scores, or hosts that were absent from the XML. A missing CVSS stays null and displays as `not provided`.
5. Every `ServiceObservation` cites an evidence ID and XPath locator. Each `Finding.evidence` item is an `EvidenceRef`; `observed` and labeled `inference` remain separate. Nessus and Burp imports create findings; nmap service observations alone do not.
6. `ActionName.ACTIVE_VALIDATE` is denied unless an exact approved, unused, unexpired approval is supplied. Existing scope and allowlisted-path checks still apply.
7. `AuditLog.append` stores the previous entry hash. `proofpath verify` recomputes the chain, verifies every artifact hash, and checks cited evidence IDs.
8. Standards references use the wording "mapped to" for OWASP, CWE, NIST SP 800-115, and MITRE ATT&CK.
9. Each tool has one status: Live, Import-only, Planned, or Unsupported. The table in section 7 is the current status.

The same rules are in `.cursor/rules/proofpath.mdc` with `alwaysApply: true`.

## 7. Integration status matrix

Status is what the code can do today.

| Tool | Status | Limitation |
| --- | --- | --- |
| Nmap | Live | Runs Ubuntu WSL Nmap 7.98 through a fixed `wsl.exe --distribution Ubuntu --exec nmap` argv prefix with `-sT`. Verified run was only against 127.0.0.1 inside WSL and returned a closed port; Windows in-process server was not reachable from WSL loopback. Recorded XML import remains labeled imported. NSE disabled. Guarded `skip_host_discovery` maps to `-Pn` and defaults off. |
| Nikto | Import-only | Imports bounded Nikto JSON or XML reports. Web configuration issues, sensitive paths, and headers are normalized with source evidence references. |
| OWASP ZAP | Import-only | Imports bounded OWASP ZAP XML or JSON alert reports. Web application alerts, CWE/WASC classifications, and solutions are normalized with evidence references. |
| Nessus | Import-only | Bounded `NessusClientData_v2` parser; synthetic fixture only, real-export details need confirmation. |
| Burp Suite | Import-only | A single validated internal DTD containing only ELEMENT/ATTLIST declarations is stripped before parsing. Entity declarations/references and SYSTEM/PUBLIC identifiers are refused; no entity resolution or network access is enabled. Host text/IP attribute and direct or nested request/response elements are supported. Message bodies stay raw. |
| ProofPath HTTP validation | Live | One approved GET/HEAD to an allowlisted path on one scoped port. No request body, caller-supplied headers, or redirect following; response capped at 4 KiB. |
| OpenVAS | Import-only | Imports bounded OpenVAS / Greenbone XML report exports. Vulnerability checks, CVSS, and CVE references are normalized with source evidence references. |
| Metasploit | Import-only | Imports human-approved, lab-controlled Metasploit findings and validation exports. Autonomous exploitation is strictly prohibited. |
| sqlmap | Unsupported | No integration and no action name. |

Recorded nmap XML, Nessus `.nessus` XML, Burp issue XML, OpenVAS/Greenbone XML, Nikto JSON/XML, OWASP ZAP XML/JSON, and Metasploit XML/JSON are available as labeled import paths. The current live nmap runtime is Ubuntu WSL, selected by `nmap.yaml`.

The same rows live in `src/proofpath/integrations.py` and `docs/INTEGRATION_MATRIX.md`. A test checks that every tool and status appear in this table. All tool import routes are available both programmatically and in the Streamlit Imports tab. Their fixture formats are synthetic; Burp accepts only a verified internal ELEMENT/ATTLIST subset and rejects entity declarations/references and external identifiers.

## 8. Security boundaries and threat model

Trust boundary: `scope.yaml` is operator input. The analyst request, DNS answers, and tool stdout are untrusted.

| Threat | Control in this build |
| --- | --- |
| Prompt injection in a banner or in XML | Raw files go to the ledger. Burp request/response bodies stay in the artifact. The proposer summary uses bounded parsed host/port/service/provenance and finding metadata inside an escaped untrusted-data block; plugin output and message bodies are excluded. The model selects by candidate ID and cannot alter Action fields, and the constructed Action passes through the guard. A regression test injects an instruction into Nessus plugin output and checks it never reaches the prompt. |
| Model invents an action | `Action` rejects unknown names and unknown fields. |
| Public or excluded target | The address must sit in an allowed CIDR and outside exclusions. |
| DNS name that resolves out of scope, or resolves to mixed addresses | Every resolved address is checked. One failure denies the action. Nmap receives the canonical IPs, not the name. |
| DNS rebinding after the check | The process does not look up the name again. |
| CIDR, range, wildcard, or comma-list target passed in the UI | Target validation accepts a single IP address or hostname; network ranges and lists are denied. |
| Encoded addresses (`127.1`, decimal, hex, IPv4-mapped IPv6) | Values that `ipaddress` rejects are denied. A mapped IPv6 address is judged as its IPv4 form. |
| `0.0.0.0`, `::`, multicast, link-local | Denied by address type. |
| Localhost | The names `localhost` and `localhost.localdomain` are denied. Other names that resolve to loopback are denied unless `allow_loopback` is true. |
| Argument injection | Unknown keys are denied. Values must be bool or int. There is no shell. |
| Forged allow decision | HMAC over the decision body. The adapter checks it. |
| Audit edit | Hash chain plus `proofpath verify`. |
| Approval bypass, replay, or self-approval | `active_validate` requires a pending request decided by another named human; a process-bound decision token and approval hash bind the state and exact target/port/method/path/finding, with expiry and single-use checks. Existing host, exclusion, port, and path checks still run. |
| HTTP redirect or SSRF | The request connects only to the scope guard's resolved address, sends no caller headers/body, permits only GET/HEAD and fixed allowlisted paths, reads at most 4 KiB, and never follows redirects. |
| Report injection | PDF text is deterministic and grounded against cited ledger evidence; unsupported AI claims are rejected and fall back to template text. |
| Accidental whole-internet scope | IPv4 prefixes shorter than /8, IPv6 prefixes shorter than /32, and prefix length 0 are rejected when the policy loads. |
| Huge tool output | Stdout above 8,000,000 bytes is not stored and produces no port rows. |
| XML doctype / XXE | Nmap permits only its exact inert `<!DOCTYPE nmaprun>` declaration and rejects internal subsets, entities, and external identifiers. Nessus refuses every DOCTYPE. Burp strips one internal subset only after verifying it contains ELEMENT/ATTLIST declarations only; entity declarations/references and SYSTEM/PUBLIC IDs are refused before XML parsing. No external entity resolver is configured. |

`proofpath redteam` uses a fake resolver and local policy for scope checks. Its approval cases bind a temporary HTTP server to 127.0.0.1; it sends no external traffic.

Assumption: an engagement lead who puts a routable range in `scope.yaml` is authorizing scans of that range. The app will run nmap there.

## 9. Setup and run instructions

Requires Python 3.11 or newer. This machine has CPython 3.13. `nmap.yaml` selects the registered Ubuntu WSL distribution; `NmapExecutionConfig` validates that setting and the adapter invokes `wsl.exe` with an argument list. Ubuntu WSL Nmap 7.98 was confirmed with `wsl --distribution Ubuntu --exec nmap --version`. Recorded XML import remains available independently.

```
py -3 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
.venv\Scripts\python -m proofpath.cli redteam
.venv\Scripts\streamlit run app.py
```

After at least one UI action or test has created a log:

```
.venv\Scripts\python -m proofpath.cli verify --audit data\audit.jsonl --ledger data\evidence
```

`verify` checks the chain, evidence artifacts, report files and citations, and approval action references. `proofpath ground-check` checks findings saved for the current report against the ledger; unsupported CVE/CWE, IP, port, product/version, or evidence-ID claims are audited and return a non-zero result. IP grounding canonicalizes IPv4 and IPv6 literals so an IPv6 address suffix cannot be mistaken for a port. PDF source labeling detects a `SYNTHETIC` marker in stored artifact bytes as well as ledger summaries.

`python -m proofpath.cli demo-load --scope scope.demo.yaml --data data/demo` imports the labeled synthetic Nmap XML, Nessus XML, and Burp XML through the normal scope-guarded import paths, then prints findings, risk ranks, proposer candidates, and the chosen plan. Pass `--all-tools` to import reports across all seven tools (including OpenVAS, Nikto, OWASP ZAP, and Metasploit). `scope.demo.yaml` is separate from the default scope and excludes `10.20.0.250` inside the demo CIDR to exercise a dropped-host audit. `docs/DEMO_SCRIPT.md` describes the rehearsal. `docs/sample_report.pdf` is generated from the synthetic evidence and is not a client report.

`scope.local-lab.yaml` is a separate loopback-only scope for `127.0.0.1:8080`, with no active validation enabled. `labs/local_target.py` accepts one local TCP connection, sends a harmless response, and exits; it contains no vulnerability and stops waiting after 90 seconds. Start it with `wsl.exe --distribution Ubuntu --cd /mnt/c/Users/RuchitRathi/Projects/proofpath --exec python3 -B -u labs/local_target.py`, then run `python -B scripts/run_local_lab.py` from the project. The runner uses `execute_action` and the configured WSL `-sT` Nmap adapter, proposes a guarded Burp import plan, and stores audit/evidence only in `.pytest-tmp/local-lab`. The benign responder creates no vulnerability finding; the demo does not invent one. No package is installed and no other project scope is widened.

`python scripts/baseline_vs_proofpath.py` runs the five-run synthetic comparison recorded in `docs/SCORECARD.md`. It is a small synthetic benchmark; its free-text baseline cannot measure structured finding drops or merges.

`ollama.yaml` configures `qwen2.5:7b-instruct-q4_K_M` with a 60-second request timeout. The frontend renders without waiting for Ollama; the sidebar's **Warm up Qwen now** button makes an explicit tiny JSON readiness request and audits success or failure. Otherwise the proposer loads the model when a plan is requested. Run `python scripts/check_ollama.py` to report reachability, list local tags through Ollama's API, report configured-tag presence, and make a schema-constrained proposer response check; the check uses only a labeled synthetic fixture. The tag is listed by the [official Ollama model library](https://ollama.com/library/qwen2.5%3A7b-instruct-q4_K_M) at about 4.7 GB. Set `PROOFPATH_OLLAMA_CONFIG` to a different YAML file to test the blank-tag fallback.

Default scope file: engagement `lab-01`, allowed `10.10.0.0/16`, excluded host `10.10.0.1`, ports 22, 80, 443, 8080, 8443. Timing is capped at 3. Host timeout is capped at 120 seconds. The UI sends timing 2 and a 60 second host timeout.

The UI has a styled dashboard header with engagement, scope, Nmap runtime, and Qwen configuration status cards, followed by Assess, Findings, Plan, Imports, Risk, Approvals, and Report tabs. Imported findings display confidence, status, sources, evidence IDs, locators, and raw excerpts; conflicts are shown with their recorded notes. Findings shows skeptic hypotheses with evidence for/against and lets the analyst queue a one-port recheck through the scope guard. Risk shows factor values, sources, weights, excluded unknowns, rank, and the capture time/evidence IDs for verified public CVE context; the operator can reload local cached context. Criticality changes are audited. Approvals show the exact HTTP action, require a distinct approver, and allow execution once. Report generates a downloadable PDF and displays its hash. Import summaries include filename, SHA-256, evidence ID when stored, tool, imported source mode, parsed and dropped counts, and parse-error count. Uploads above 25,000,000 bytes are rejected before XML parsing. Plan shows distinct action candidates, evidence-aware risk facts, duplicate-skip reasons, and AI inference with approve/skip controls; the grounding verifier hides unsupported model rationale. Approving an Nmap candidate queues it; a separate button runs only its one selected port through the guard. Burp/Nessus import candidates require an analyst-supplied XML file in Imports. AppTest replaces the process runner so UI tests do not start WSL nmap. The nmap `-Pn` option is a guarded boolean and defaults off.

The proposer uses the local `/api/chat` interface when a confirmed tag is configured. ReportLab generates deterministic landscape A4 PDFs with a vector severity chart. `python -m pip install -e ".[dev]"` installs ReportLab.

## 10. LIVE DEMO CHECKLIST (organizers' 7 points)

| # | Checklist item | Status today | Demo action |
| --- | --- | --- | --- |
| 1 | Authorized target and scope validation | Done | Show scope.yaml, run redteam, deny 8.8.8.8 and excluded 10.10.0.1. |
| 2 | Plan with reasoning | Implemented; score unverified | Show how live/imported provenance changes the available next steps, the code-generated risk factors, Qwen's evidence-cited rationale, and separate guarded run/approval controls. |
| 3 | Multi-tool execute/import with real status | Partial | Live nmap when installed; otherwise import recorded XML and show `imported`. No second scanner is built. |
| 4 | Normalization, correlation, and false-positive handling | Partial | Show merged sources/evidence, conflict notes, skeptic hypothesis and evidence links, then queue a one-port recheck for analyst review. |
| 5 | Risk prioritization and approval checkpoint | Done | Review the factor-ranked table, request a single GET/HEAD check, approve as another named human, run once, and replay to see denial. |
| 6 | Download report and trace a finding to raw evidence | Done | Generate/download the deterministic PDF, then resolve a finding's evidence ID, locator, excerpt, and artifact SHA-256 in its appendices. |
| 7 | Safe failure and honest unsupported integrations | Done | Show a denied scope, missing nmap handling, and the integration matrix. |

### Manual verification and tamper demo

Run `python -m proofpath.cli verify --audit data/audit.jsonl --ledger data/evidence`. For artifact detection, copy the evidence directory and audit log into a disposable folder, change one byte in an `EV-*.bin`, and rerun using the copied paths; verify must name the evidence ID. Restore a clean copy, edit one JSONL audit line without recomputing its hash, and rerun; verify must name the broken sequence. Never tamper with the only copy of engagement evidence.

### Docker and self-hosted labs on Windows

Docker Desktop commonly publishes a container on `127.0.0.1`, denied by default. Keep the default policy unchanged. For an authorized local container, set `allow_loopback: true`, add `127.0.0.1/32` to `allowed_cidrs`, and list only its published ports in `allowed_ports`. Alternatively, use a VM on a host-only network such as `192.168.56.0/24`, and authorize only that CIDR. Confirm the actual lab range before scanning.

The eight weighted judging criteria remain in section 3; the seven live-demo items above are a separate checklist.

## 11. Known limitations and assumptions

- The configured Ollama model is local and optional at runtime. UI request text is not interpreted as instructions to a tool; model response quality depends on schema validation and analyst review.
- Approval state is process-local in the Streamlit session; the durable audit log records request, decision, execution, and outcome. A process restart invalidates in-memory approvals. The skeptic is rule-based and does not update status from hypotheses alone.
- Nmap argv is `nmap -sT -oX -` plus optional `-sV`, `-Pn` (only when its guarded boolean is true), `-T{n}`, `--host-timeout`, `-p`, and canonical IPs. TCP connect scanning is explicit for WSL compatibility. Host discovery is on by default. NSE scripts are never passed.
- A timeout stores whatever stdout was captured and does not turn it into port rows.
- A non-zero exit with parseable XML is status `error`, and the parsed rows are still returned because they were in the document.
- Excluded hostnames resolve at policy load and their addresses are added to exclusions. An unresolvable excluded hostname rejects the policy.
- IPv4 allow-lists must be /8 or longer. IPv6 allow-lists must be /32 or longer.
- The HMAC key is process memory. It is not the audit chain. Restarting Streamlit creates a new key. Decisions are not reused across runs.
- All files under `tests/fixtures/` are synthetic fixtures, not client scan data. Nessus plugin ID/CVE values are placeholders. `burp_with_internal_dtd.xml` mimics the safe ELEMENT/ATTLIST subset shape. Unverified Burp details: exact declarations and optional fields across current Burp versions, host element variations, and request/response nesting/base64 placement; validate them against an actual export.
- Scanning is limited to ranges a person put in `scope.yaml`. Confirm the lab range before a live demo. The default `10.10.0.0/16` may or may not be the hackathon lab.
