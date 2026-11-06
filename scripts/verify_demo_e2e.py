import hashlib, json, socket, tempfile, threading, yaml
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from proofpath.adapters.active_validate import ActiveValidationAdapter
from proofpath.adapters.base import execute_action
from proofpath.approval import decide_approval, request_approval
from proofpath.audit import AuditLog
from proofpath.cli import main
from proofpath.ledger import Ledger
from proofpath.report.generator import generate_pdf
from proofpath.schemas import Action, ActionName, Finding
from proofpath.scope_guard import ScopeGuard
from proofpath.adapters.nmap import parse_nmap_xml
from proofpath.risk import rank_findings

class Handler(BaseHTTPRequestHandler):
 def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"synthetic approved response")
 def log_message(self,*args): pass

data=Path('data/demo'); audit=AuditLog(data/'audit.jsonl'); ledger=Ledger(data/'evidence')
server=HTTPServer(('127.0.0.1',0),Handler); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
try:
 raw=yaml.safe_load(Path('scope.demo.yaml').read_text(encoding='utf-8')); raw['allowed_cidrs'].append('127.0.0.1/32'); raw['allow_loopback']=True; raw['allowed_ports'].append(str(server.server_port)); raw['enabled_actions'].append('active_validate'); raw['allowed_validation_paths']=['/']
 with tempfile.TemporaryDirectory(prefix='proofpath-demo-scope-') as tmp:
  scope=Path(tmp)/'scope.yaml'; scope.write_text(yaml.safe_dump(raw),encoding='utf-8'); guard=ScopeGuard.from_yaml(scope)
  findings=[Finding.model_validate(x) for x in json.loads((data/'current-findings.json').read_text(encoding='utf-8'))]
  finding=findings[0]
  action=Action(id='demo-active-once',name=ActionName.ACTIVE_VALIDATE,target='127.0.0.1',ports=[server.server_port],arguments={'method':'GET','path':'/','finding_id':finding.id},engagement_id=guard.policy.engagement,requested_by='demo-requester')
  approval=request_approval(action,'demo-requester','synthetic demo exact-action approval')
  audit.append('approval_requested','demo-requester',{'approval_id':approval.id,'action_id':action.id,'action_hash':approval.action_hash,'requested_by':approval.requested_by,'action':action.model_dump(mode='json'),'justification':approval.justification,'expires_at':approval.expires_at.isoformat()})
  approval=decide_approval(approval,'demo-approver',approved=True)
  audit.append('approval_decision','demo-approver',{'approval_id':approval.id,'action_id':action.id,'action_hash':approval.action_hash,'requested_by':approval.requested_by,'decided_by':approval.decided_by,'state':approval.state.value,'decided_at':approval.decided_at.isoformat()})
  adapter=ActiveValidationAdapter(action,approval)
  first=execute_action(action,guard,audit,ledger,{ActionName.ACTIVE_VALIDATE:adapter},approval=approval)
  replay=execute_action(action,guard,audit,ledger,{ActionName.ACTIVE_VALIDATE:adapter},approval=approval)
  print('approval_execute:',first.status,first.message,'replay:',replay.status,replay.message)
  nraw=Path('tests/fixtures/demo/nmap.xml').read_bytes(); nmap_ev=next(ev for ev in (ledger.load(p.stem) for p in ledger.root.glob('EV-*.json')) if ev.tool=='nmap')
  observations=[item.model_copy(update={'source_mode':'imported'}) for item in parse_nmap_xml(ledger.read_bytes(nmap_ev.id),nmap_ev.id)]
  report=Path('docs/sample_report.pdf')
  result=generate_pdf(findings,observations,ledger,audit,report,engagement='demo-synthetic',scope_cidrs=['10.20.0.0/24'])
  print('report:',json.dumps(result))
  code=main(['verify','--audit',str(data/'audit.jsonl'),'--ledger',str(data/'evidence')]); print('verify_exit:',code)
  good=report.read_bytes(); report.write_bytes(good[:-1]+bytes([good[-1]^1])); print('tampered_pdf_verify_exit:',main(['verify','--audit',str(data/'audit.jsonl'),'--ledger',str(data/'evidence')])) ; report.write_bytes(good)
  artifact=Path(nmap_ev.artifact_path); original=artifact.read_bytes(); artifact.write_bytes(original[:-1]+bytes([original[-1]^1])); print('tampered_artifact_verify_exit:',main(['verify','--audit',str(data/'audit.jsonl'),'--ledger',str(data/'evidence')])) ; artifact.write_bytes(original)
finally:
 server.shutdown();server.server_close();thread.join(timeout=2)
