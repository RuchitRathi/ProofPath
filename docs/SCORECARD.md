# Baseline vs ProofPath scorecard

Date: 2026-11-07  
Model: `qwen2.5:7b-instruct-q4_K_M`  
Command: `python scripts/baseline_vs_proofpath.py`  
Runs: 5 per method on the same labeled synthetic demo fixture set.

This is a small synthetic benchmark, not a general performance or accuracy claim. The direct baseline received parsed findings text and returned a JSON summary. It had no evidence ledger, candidate gate, or grounding verifier. ProofPath imported the same fixture data through its guarded importers, deterministically correlated findings, and asked the model to select a candidate ID.

| Metric | Direct Qwen baseline | ProofPath |
|---|---:|---:|
| Valid JSON | 5/5 (100%) | 5/5 (100%) |
| Fabricated CVE/CWE/IP/port/evidence claims detected mechanically | 0 | 0 |
| Findings dropped or incorrectly merged | Not measurable: baseline returns free text, not a structured finding set | 0; 6 findings returned in each run |
| Model calls | 5 | 5 |
| Average wall time | 6.876 s | 22.009 s |
| Safe rule fallbacks | N/A | 2/5 |
| Candidate choice | N/A | C1 in all five runs |

The baseline did as well or better on JSON validity and detected fabricated claims, and it was faster. It often omitted facts: four of five baseline responses had no extractable CVE, CWE, IP, port, or evidence ID claims; one returned several supported facts. This does not establish that the baseline preserved all findings, and incorrect drops/merges cannot be measured from its unstructured summary. ProofPath retained all six deterministic findings and built a candidate action from C1, while its measured latency was higher and two runs used the deterministic fallback.

Fallback audit reasons included candidate-irrelevant evidence citations, evidence IDs absent from the ledger, and Ollama request timeouts. The harness records those rejection events; the two fallback runs included timeout and citation rejection cases. This result motivated the Day 4 timeout and prompt follow-up.

The mechanical claim check compares identifiers and addresses against the fixture inputs, ports against fixture ports, and evidence IDs against the labeled parsed baseline text / active ledger. It does not judge the semantic quality of prose or whether a summary is complete.

## Repeat after proposer timeout/prompt correction

Date: 2026-11-07. Exact command: `python scripts/baseline_vs_proofpath.py`. A real warm-up was run immediately before the harness. The harness remained five runs per method.

| Metric | Direct Qwen baseline | ProofPath |
|---|---:|---:|
| Valid JSON | 5/5 (100%) | 5/5 (100%) |
| Mechanically detected fabricated claims | 0 | 0 |
| Findings dropped/incorrectly merged | Not measurable from free text | 0; 6 each run |
| Model calls | 5 | 5 |
| Average wall time | 2.300 s | 15.570 s |
| Final safe fallbacks | N/A | 0/5 |
| Candidate selected | N/A | C1 in every run |

ProofPath retried two rejected first responses (one timeout, one citation ID absent from the ledger); both retries recovered without fallback. The baseline was still faster and often returned no extractable claims. These five-run observations are not a general benchmark.
