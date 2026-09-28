import pathlib,json,subprocess,os,time,hashlib,re,urllib.request,urllib.error,signal,socket,base64,sys
root=pathlib.Path('/Users/huseyinarslan/.codex/worktrees/arcora-local-verification/dark-perp')
scratch=pathlib.Path('/tmp/arcora-extension-wallet-2vhdkiab')
old=json.loads((scratch/'runtime.json').read_text())
(scratch/'runtime-initial.json').write_text(json.dumps(old,indent=2)+'\n')
env={'PATH':os.environ['PATH'],'HOME':os.environ['HOME']}
origin='http://127.0.0.1:49399'; upstream='http://127.0.0.1:49395'
runtime={**old,'status':'STARTING','supervisor_pid':os.getpid(),'processes':[],'allowed_origins':[origin],'restart_reason':'Exact browser proxy origin was missing from gateway allowlist; initial GET-only smoke did not detect POST/WS refusal. Existing snapshot and origin retained.','logs':{'gateway':str(scratch/'gateway-v2.log'),'proxy':str(scratch/'proxy-v2.log')},'smoke':{}}
processes=[]
def save(): (scratch/'runtime.json').write_text(json.dumps(runtime,indent=2)+'\n')
def start(kind,args,childenv):
 with pathlib.Path(runtime['logs'][kind]).open('wb') as f: p=subprocess.Popen(args,cwd=root,env=childenv,stdout=f,stderr=subprocess.STDOUT)
 processes.append(p); runtime['processes'].append({'kind':kind,'pid':p.pid}); save(); return p
def ready(p,kind,pattern):
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  if p.poll() is not None: raise RuntimeError(kind+' exited '+str(p.returncode))
  if re.search(pattern,pathlib.Path(runtime['logs'][kind]).read_text()): return
  time.sleep(.1)
 raise RuntimeError(kind+' start timed out')
def cleanup(*_):
 runtime['status']='STOPPING'; save()
 for p in reversed(processes):
  if p.poll() is None: p.terminate()
 for p,r in zip(processes,runtime['processes']):
  try:r['exit_code']=p.wait(timeout=40)
  except subprocess.TimeoutExpired:p.kill();r['exit_code']=p.wait(timeout=10)
 runtime['status']='STOPPED';save();raise SystemExit(0)
def post(origin_header):
 req=urllib.request.Request(origin+'/v1/accounts',data=b'{}',headers={'Content-Type':'application/json','Origin':origin_header},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=10) as r:
   body=json.load(r)
   assert isinstance(body.get('owner'),str) and isinstance(body.get('apiKey'),str)
   return r.status
 except urllib.error.HTTPError as e:return e.code
def websocket(path,origin_header):
 with socket.create_connection(('127.0.0.1',49399),timeout=10) as sock:
  key=base64.b64encode(os.urandom(16)).decode()
  req=f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:49399\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origin_header}\r\n\r\n'
  sock.sendall(req.encode())
  data=b''
  while b'\r\n\r\n' not in data:
   part=sock.recv(4096)
   if not part:raise RuntimeError('No WS handshake response')
   data+=part
  status=int(data.split(b' ',2)[1])
  if status==101:
   assert b'sec-websocket-accept:' in data.lower()
   sock.sendall(bytes([0x88,0x80])+os.urandom(4))
  return status
signal.signal(signal.SIGTERM,cleanup);signal.signal(signal.SIGINT,cleanup)
try:
 assert hashlib.sha256((root/'target/debug/gateway').read_bytes()).hexdigest()==old['gateway_binary_sha256']
 gw=start('gateway',[str(root/'target/debug/gateway')],{**env,'GATEWAY_BIND_ADDRESS':'127.0.0.1','PORT':'49395','DARKPERP_STATE':old['snapshot_path'],'GATEWAY_ALLOWED_ORIGINS':origin})
 ready(gw,'gateway',r'listening on http://127\.0\.0\.1:49395')
 proxy=start('proxy',['node',str(root/'scripts/local-verification/serve_gateway_browser.mjs'),str(scratch/'build'),upstream,'49399'],env)
 ready(proxy,'proxy',r'"url":"http://127\.0\.0\.1:49399"')
 runtime['smoke']['allowed_origin_account_post']=post(origin)
 assert runtime['smoke']['allowed_origin_account_post']==200
 runtime['smoke']['untrusted_origin_account_post']=post('https://untrusted.invalid')
 assert runtime['smoke']['untrusted_origin_account_post']==403
 for path in ['/ws','/v1/ws']:
  status=websocket(path,origin);runtime['smoke'][path+'_allowed_origin_handshake']=status;assert status==101
  status=websocket(path,'https://untrusted.invalid');runtime['smoke'][path+'_untrusted_origin_handshake']=status;assert status==403
 with urllib.request.urlopen(origin,timeout=10) as r:
  assert r.status==200 and r.headers['Content-Security-Policy']==runtime['csp']
 runtime['smoke']['strict_csp_index']=200
 runtime['status']='RUNNING';save()
 print(json.dumps({'runtime':str(scratch/'runtime.json'),'browser_url':origin,'gateway_url':upstream,'supervisor_pid':os.getpid(),'processes':runtime['processes'],'smoke':runtime['smoke']}),flush=True)
 while True:
  if any(p.poll() is not None for p in processes):raise RuntimeError('Owned service exited')
  time.sleep(1)
except BaseException as e:
 if not isinstance(e,SystemExit):print(str(e),file=sys.stderr,flush=True)
 cleanup()
