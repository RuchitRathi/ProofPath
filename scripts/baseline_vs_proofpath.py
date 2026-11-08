"""Small synthetic comparison: direct Qwen text vs ProofPath candidate selection."""
import json, re, tempfile, time
from pathlib import Path
from proofpath.adapters.burp_import import import_burp_xml
from proofpath.adapters.nessus_import import import_nessus_xml
from proofpath.adapters.nmap import parse_nmap_xml
from proofpath.audit import AuditLog
from proofpath.correlator import correlate_findings
from proofpath.ledger import Ledger
from proofpath.proposer import OllamaClient, OllamaConfig, RulePlanner, propose_and_gate
from proofpath.scope_guard import ScopeGuard
from proofpath.selftest import demo_resolver

ROOT=Path(__file__).resolve().parents[1]; FIX=ROOT/'tests'/'fixtures'/'demo'
guard=ScopeGuard.from_yaml(ROOT/'scope.demo.yaml',resolver=demo_resolver)
client=OllamaClient(OllamaConfig.from_yaml(ROOT/'ollama.yaml'))
raws={name:(FIX/name).read_bytes() for name in ('nmap.xml','nessus.nessus','burp.xml')}
grounded_cves=set(re.findall(rb'CVE-\d{4}-\d{4,}',b' '.join(raws.values())))
grounded_cwes=set(re.findall(rb'CWE-\d+',b' '.join(raws.values())))
grounded_ips=set(re.findall(rb'10\.20\.0\.\d+',b' '.join(raws.values())))
grounded_ports=set(re.findall(rb'(?:portid|port|:)[=" ]+(\d{1,5})',b' '.join(raws.values())))
summary='''SYNTHETIC / IMPORTED parsed findings (not client results):\nF1 10.20.0.10:80 high confirmed CVE-2099-900001 CWE-79 evidence EV-0001 EV-0002\nF2 10.20.0.10:443 low suspected CWE-89 evidence EV-0003\nF3 10.20.0.10:8443 low false_positive_candidate CWE-200 evidence EV-0003 EV-0001\nF4 10.20.0.11:80 medium suspected CVE-2099-900001 CWE-79 evidence EV-0002 EV-0004\nF5 10.20.0.10:8080 medium suspected CWE-20 evidence EV-0004\n'''
grounded_evidence=set(re.findall(rb'EV-\d{4,}',summary.encode()))
def claim_counts(text):
 vals={k:set(re.findall(pattern,text.encode(),re.I)) for k,pattern in {'CVE':rb'CVE-\d{4}-\d{4,}','CWE':rb'CWE-\d+','IP':rb'\b(?:\d{1,3}\.){3}\d{1,3}\b','evidence':rb'EV-\d{4,}'}.items()}
 vals['port']=set(re.findall(rb'\bport\s+(\d{1,5})\b',text.encode(),re.I))|set(re.findall(rb'(?<!\d):([0-9]{1,5})\b',text.encode()))
 allowed={'CVE':grounded_cves,'CWE':grounded_cwes,'IP':grounded_ips,'port':grounded_ports,'evidence':grounded_evidence}
 return sum(len(v-allowed[k]) for k,v in vals.items()),vals
def build_case():
 with tempfile.TemporaryDirectory(prefix='baseline-proofpath-') as d:
  root=Path(d); audit=AuditLog(root/'audit.jsonl'); ledger=Ledger(root/'evidence')
  n=import_nessus_xml(raws['nessus.nessus'],guard,audit,ledger); b=import_burp_xml(raws['burp.xml'],guard,audit,ledger)
  ne=ledger.store(content=raws['nmap.xml'],tool='nmap',command=['import_nmap_xml'],status='ok',summary='synthetic nmap demo',source_mode='imported')
  obs=parse_nmap_xml(raws['nmap.xml'],ne.id); findings=correlate_findings([*n.findings,*b.findings],obs)
  return root,audit,ledger,obs,findings
baseline=[]; proof=[]
for i in range(5):
 start=time.perf_counter(); raw=client.complete([{'role':'user','content':'Write a concise findings summary with reported CVEs, CWEs, IP addresses, ports, and evidence IDs. Use only the following parsed text; do not add unsupported facts.\n'+summary}],{'type':'object','properties':{'summary':{'type':'string'}},'required':['summary'],'additionalProperties':False})
 elapsed=time.perf_counter()-start
 try: parsed=json.loads(raw); text=parsed['summary']; valid=True
 except Exception: text=raw; valid=False
 fake,claims=claim_counts(text); baseline.append({'valid_json':valid,'fabricated_claims':fake,'mentions':{k:len(v) for k,v in claims.items()},'seconds':elapsed})
for i in range(5):
 with tempfile.TemporaryDirectory(prefix='baseline-proofpath-proof-') as d:
  root=Path(d); audit=AuditLog(root/'audit.jsonl'); ledger=Ledger(root/'evidence')
  n=import_nessus_xml(raws['nessus.nessus'],guard,audit,ledger); b=import_burp_xml(raws['burp.xml'],guard,audit,ledger)
  ne=ledger.store(content=raws['nmap.xml'],tool='nmap',command=['import_nmap_xml'],status='ok',summary='synthetic nmap demo',source_mode='imported')
  obs=parse_nmap_xml(raws['nmap.xml'],ne.id); findings=correlate_findings([*n.findings,*b.findings],obs)
  start=time.perf_counter(); candidates=RulePlanner().candidates(obs,guard.policy.engagement,findings=findings,enabled_actions=set(guard.policy.enabled_actions))
  proposal,result,fallback=propose_and_gate(obs,candidates,client,guard,audit,ledger,findings=findings); elapsed=time.perf_counter()-start
  text=json.dumps(proposal.model_dump(mode='json')) if proposal else ''; fake,claims=claim_counts(text)
  if proposal:
   chosen=next((c for c in candidates if c.candidate_id==proposal.candidate_id),None)
   if chosen and proposal.action.model_dump(mode='json')==chosen.action.model_dump(mode='json'):
    claims['IP'].add(chosen.action.target.encode()); claims['port'].update(str(p).encode() for p in chosen.action.ports)
   else: fake+=1
  rejected=[e.details.get('reason','') for e in audit.read_entries() if e.event_type=='model_output_rejected']
  proof.append({'valid_json':proposal is not None and result is not None,'fabricated_claims':fake,'findings_count':len(findings),'fallback':fallback,'candidate_id':proposal.candidate_id if proposal else None,'seconds':elapsed,'rejection_reasons':rejected})
def avg(rows,key): return round(sum(x[key] for x in rows)/len(rows),3)
out={'model_tag':OllamaConfig.from_yaml(ROOT/'ollama.yaml').model_tag,'runs_per_method':5,'baseline':{'valid_json_rate':sum(x['valid_json'] for x in baseline)/5,'fabricated_claims':sum(x['fabricated_claims'] for x in baseline),'findings_dropped_or_merged_incorrectly':'not meaningfully measurable from free-text summary; it has no structured finding set','model_calls':5,'average_seconds':avg(baseline,'seconds'),'runs':baseline},'proofpath':{'valid_json_rate':sum(x['valid_json'] for x in proof)/5,'fabricated_claims':sum(x['fabricated_claims'] for x in proof),'findings_dropped_or_merged_incorrectly':0 if all(x['findings_count']==6 for x in proof) else 'see run counts','findings_per_run':[x['findings_count'] for x in proof],'model_calls':sum(1 for x in proof if x['candidate_id']),'average_seconds':avg(proof,'seconds'),'fallback_count':sum(x['fallback'] for x in proof),'fallback_rejection_reasons':[reason for x in proof for reason in x['rejection_reasons']],'candidate_ids':[x['candidate_id'] for x in proof]}}
print(json.dumps(out,indent=2))
