import hashlib, json, socket, threading, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import yaml
from proofpath.adapters.nmap import NmapAdapter, NmapExecutionConfig
from proofpath.audit import AuditLog
from proofpath.ledger import Ledger
from proofpath.schemas import Action, ActionName
from proofpath.scope_guard import ScopeGuard

class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(b"loopback test")
 def log_message(self,*args): pass

server=HTTPServer(("127.0.0.1",0),Handler); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
try:
 with tempfile.TemporaryDirectory(prefix="proofpath-wsl-loopback-") as td:
  root=Path(td); raw=yaml.safe_load(Path("scope.yaml").read_text(encoding="utf-8")); raw.update(engagement="loopback-test",allowed_cidrs=["127.0.0.1/32"],excluded_cidrs=[],excluded_hosts=[],allowed_ports=[str(server.server_port)],allow_loopback=True,enabled_actions=["nmap_scan"])
  (root/"scope.yaml").write_text(yaml.safe_dump(raw),encoding="utf-8")
  guard=ScopeGuard.from_yaml(root/"scope.yaml"); audit=AuditLog(root/"audit.jsonl"); ledger=Ledger(root/"evidence")
  action=Action(id="wsl-loopback-only",name=ActionName.NMAP_SCAN,target="127.0.0.1",ports=[server.server_port],arguments={"service_detection":False,"skip_host_discovery":True,"timing":2,"host_timeout_seconds":15},engagement_id="loopback-test",requested_by="day4-verification")
  config=NmapExecutionConfig.from_yaml("nmap.yaml"); result=NmapAdapter(wsl_distribution=config.distribution).run(guard.check(action),guard,audit,ledger,"day4-verification")
  print(json.dumps({"status":result.status,"reason":result.message,"evidence_id":result.evidence_id,"sha256":result.sha256,"services":[x.model_dump(mode="json") for x in result.services]},indent=2))
  if result.evidence_id:
   data=ledger.read_bytes(result.evidence_id); text=data.decode("utf-8",errors="strict"); ev=ledger.load(result.evidence_id)
   print(json.dumps({"byte_length":len(data),"sha256_actual":hashlib.sha256(data).hexdigest(),"sha256_metadata":ev.sha256,"hash_matches":hashlib.sha256(data).hexdigest()==ev.sha256,"utf8_strict":True,"crlf_count":data.count(b"\r\n"),"lf_count":data.count(b"\n"),"ends_newline":data.endswith(b"\n"),"nmap_xml_prefix":text[:80]},indent=2))
finally:
 server.shutdown(); server.server_close(); thread.join(timeout=2)
