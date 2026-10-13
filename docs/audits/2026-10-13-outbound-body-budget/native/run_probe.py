import datetime,hashlib,json,shlex,shutil,socket,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path.cwd();OUT=ROOT/'target/outbound-body-validation-20261013/recovery/owned-body-probe'
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,b):
 with p.open('xb') as f:f.write(b)
rc=subprocess.check_output(['rustup','which','--toolchain','1.99.0','rustc'],text=True).strip();curl=shutil.which('curl');assert curl
deps=ROOT/'target/debug/deps';libs={n:max(deps.glob('lib'+n+'-*.rlib'),key=lambda p:p.stat().st_mtime) for n in ['prover','postcard','serde_json']};cmd=[rc,'--edition=2021','--crate-name','owned_outbound_body_probe',str(OUT/'probe.rs'),'-L','dependency='+str(deps)]
for n,p in libs.items():cmd.extend(['--extern',n+'='+str(p)])
cmd.extend(['-o',str(OUT/'probe')]);start=time.monotonic();r=subprocess.run(cmd,capture_output=True,timeout=30);save(OUT/'compile.stdout.log',r.stdout);save(OUT/'compile.stderr.log',r.stderr);compile={'command':cmd,'exit_code':r.returncode,'seconds':time.monotonic()-start,'probe_source_sha256':sha((OUT/'probe.rs').read_bytes()),'libs_sha256':{n:sha(p.read_bytes()) for n,p in libs.items()},'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)};save(OUT/'compile.json',(json.dumps(compile,indent=2)+'\n').encode());assert r.returncode==0,r.stderr.decode()
cuts=subprocess.run([str(OUT/'probe'),'cuts'],capture_output=True,timeout=3);save(OUT/'cuts.stdout.log',cuts.stdout);save(OUT/'cuts.stderr.log',cuts.stderr);assert cuts.returncode==0;cut=json.loads(cuts.stdout)
assert cut['pure']['shared_JSON_ceil']==512*1024*1024
assert cut['pure']['max_numeric_boundary']=='Ok(())' and cut['pure']['max_numeric_plus1']=='Err(RequestBodyLimit)'
for n in ['plaintext_usize_MAX_overflow','wire_usize_MAX_overflow','wire_multiplication_edge_overflow']:assert cut['pure'][n]=='Err(RequestBodyLimit)'
for n in ['early_exact','actual_exact']:assert len(cut[n]['phases'])==2 and cut[n]['result']=='Ok(467)'
for n in ['early_over','actual_over']:assert len(cut[n]['phases'])==1 and cut[n]['result']=='Err(Http("HTTP request exceeds byte limit"))'
version=subprocess.check_output([curl,'--version'],text=True)
results={}
def case(label,body,budget,status=200):
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(.1);stop=threading.Event();requests=[];errors=[]
 def serve():
  try:
   deadline=time.monotonic()+10
   while not requests:
    try:conn,peer=listener.accept()
    except socket.timeout:
     if stop.is_set():break
     assert time.monotonic()<deadline;continue
    assert peer[0]=='127.0.0.1'
    with conn:
     conn.setblocking(True);conn.settimeout(3);data=b''
     while b'\r\n\r\n' not in data:
      b=conn.recv(8192);assert b;data+=b;assert len(data)<256*1024
     header,payload=data.split(b'\r\n\r\n',1);length=int(next(x.split(b':',1)[1].strip() for x in header.split(b'\r\n') if x.lower().startswith(b'content-length:')))
     assert length==len(body)
     while len(payload)<length:
      b=conn.recv(min(8192,length-len(payload)));assert b;payload+=b
     assert payload==body;assert header.split(b'\r\n')[0]==b'POST /base/prove HTTP/1.1';assert b'Authorization: Bearer synthetic-bearer' in header
     response=b'{"owned_fixture":1}';conn.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: {len(response)}\r\nConnection: close\r\n\r\n'.encode()+response);conn.shutdown(socket.SHUT_WR)
     try:conn.recv(1)
     except (socket.timeout,ConnectionResetError):pass
     wire=header+b'\r\n\r\n'+payload;save(OUT/(label+'.request.bin'),wire);requests.append({'method_target':header.split(b'\r\n')[0].decode(),'body_bytes':len(payload),'body_sha256':sha(payload),'wire_sha256':sha(wire),'synthetic_bearer_exact':True,'response_status':status})
  except BaseException as e:errors.append(type(e).__name__+': '+str(e))
  finally:listener.close()
 port=listener.getsockname()[1];thread=threading.Thread(target=serve);thread.start();bodyfile=OUT/(label+'.body.bin');save(bodyfile,body);marker=OUT/(label+'.child-marker');wrapper=OUT/(label+'.wrapper.sh');save(wrapper,('#!/bin/sh\nprintf "owned child started\\n" > '+shlex.quote(str(marker))+'\nexec '+shlex.quote(curl)+' "$@"\n').encode());wrapper.chmod(0o700)
 try:
  start=time.monotonic();run=subprocess.run([str(OUT/'probe'),'http',f'http://127.0.0.1:{port}/base/',str(bodyfile),str(budget),str(wrapper)],capture_output=True,timeout=15)
 finally:stop.set();thread.join(timeout=5)
 save(OUT/(label+'.stdout.log'),run.stdout);save(OUT/(label+'.stderr.log'),run.stderr);assert run.returncode==0 and not thread.is_alive() and not errors,errors
 return {'exit_code':run.returncode,'seconds':time.monotonic()-start,'stdout_sha256':sha(run.stdout),'stderr_sha256':sha(run.stderr),'returned':json.loads(run.stdout),'wrapper_sha256':sha(wrapper.read_bytes()),'child_started':marker.exists(),'requests':requests,'actual_request_count':len(requests),'public_input_body_sha256':sha(body)}
basebody=('{"owned":"'+'x'*(160*1024-12)+'"}').encode();assert len(basebody)==160*1024
utf8='{"owned":"ğ🙂"}'.encode()
for label,body,budget,status,accepted in [('ascii-exact',basebody,len(basebody),200,True),('ascii-plus1',basebody+b'\n',len(basebody),200,False),('utf8-exact',utf8,len(utf8),200,True),('utf8-char-limit',utf8,len(utf8.decode()),200,False),('zero-budget',b'{"owned":1}',0,200,False),('typed401',b'{"owned":1}',11,401,True)]:
 v=case(label,body,budget,status);results[label]=v;assert v['returned']['body_bytes']==len(body)
 if accepted:
  assert v['child_started'] and v['actual_request_count']==1;assert v['requests'][0]['body_sha256']==sha(body)
  if status==200:assert v['returned']['returned']['kind']=='OK' and v['returned']['returned']['JSON_response_accepted']
  else:assert v['returned']['returned']=={'kind':'ERROR','error':'Unauthorized'}
 else:
  assert not v['child_started'] and v['actual_request_count']==0;error='invalid HTTP transport limits' if budget==0 else 'HTTP request exceeds byte limit';assert v['returned']['returned']=={'kind':'ERROR','error':'Http("'+error+'")'}
sys.path.insert(0,str(ROOT/'scripts/local-verification'));import candidate_identity_manifest as identity
before=json.loads((OUT/'source-snapshot.json').read_bytes());after=identity.source_inventory(ROOT);assert after==before['source_files_sha256'];base=json.loads((ROOT/'target/outbound-body-validation-20261013/recovery/base-source.json').read_bytes());assert all(sha((ROOT/'target/outbound-body-validation-20261013/recovery/base-source'/p).read_bytes())==m['sha256'] for p,m in base['files'].items())
record={'schema':'arcora-owned-outbound-body-native-probe/v1','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,'source_count':len(after),'source_sha256':sha(identity.canonical(after)),'source_before_after_equal':True,'base5archive_unchanged':True,'source_snapshot_sha256':sha((OUT/'source-snapshot.json').read_bytes()),'extraction_sha256':sha((OUT/'extraction.json').read_bytes()),'compile':compile,'native_curl':curl,'curl_version':version,'HTTP_cases':results,'actual_HTTP_requests':sum(v['actual_request_count'] for v in results.values()),'refused_cases_zerochild_zerorequest':[n for n,v in results.items() if not v['child_started'] and v['actual_request_count']==0],'isolated_cuts_and_numeric_size_helpers':cut,'cuts_stdout_sha256':sha(cuts.stdout),'cuts_stderr_sha256':sha(cuts.stderr),'scope':'AFTER only exact frozen source/helper/full POST function with small injected test budgets and nativecurl/ownedloopback/syntheticbearer. 512MiB and usize-overflow cases pure integers ONLY, no hugeallocation or current512MiB request acceptance claim. Isolated synthetic plaintext/wire guard snippets use inert continuation sentinels, NOT wholehandshake/keyrelease/crypto sealing proofs. Plaintext is allocated before early cut; post-serialization guards do not prevent prior allocations. Typed401 tested at lowlevel only, no rehandshake/backend/prove/boot/env/config/privatecredentials/realendpoint. Originalbase archives preserved, no invented beforefailure.'}
save(OUT/'result.json',(json.dumps(record,indent=2)+'\n').encode())
print(json.dumps({'passed':True,'result_sha256':sha((OUT/'result.json').read_bytes()),'source_before_after_equal':True,'source':str(len(after))+'/'+record['source_sha256'],'HTTP_cases':len(results),'actual_requests':record['actual_HTTP_requests'],'zerochild_zerorequest_refusals':record['refused_cases_zerochild_zerorequest'],'early_cut_true_scope':'isolated sentinel only, plaintext alreadyallocated'},indent=2))
