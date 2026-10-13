import datetime,hashlib,json,re,socket,subprocess,threading,time,shutil,sys
from pathlib import Path
ROOT=Path.cwd();OUT=ROOT/'target/service-base-validation-20261013/recovery/before-native-probe'
SOURCES=OUT/'base-sources';SNAP=json.loads((OUT/'base-snapshot.json').read_bytes())
def sha(data):return hashlib.sha256(data).hexdigest()
def source(path):
 meta=SNAP['exact_git_blobs'][path];raw=(SOURCES/meta['file']).read_bytes();assert sha(raw)==meta['sha256'];return raw.decode()
def function(text,name):
 m=re.search(r'(?m)^(?:pub(?:\([^)]*\))?\s+)?fn '+name+r'\(',text);assert m
 start=m.start();brace=text.index('{',m.end());depth=0
 for i in range(brace,len(text)):
  if text[i]=='{':depth+=1
  elif text[i]=='}':
   depth-=1
   if depth==0:return text[start:i+1]
 raise AssertionError('function extraction')
main=source('crates/gateway/src/main.rs');pv=source('crates/prover-service/src/main.rs');pc=source('crates/gateway/src/prover_client.rs')
gets=[function(main,n) for n in ['http_get_json','http_get_json_command']];assert gets==[function(pv,n) for n in ['http_get_json','http_get_json_command']]
post=[function(pc,n) for n in ['prove_curl_args','split_status','http_post','http_post_command']]
constants='\n'.join(re.findall(r'(?m)^const (?:STATUS_SENTINEL|MAX_PROVE_RESPONSE_BYTES):[^\n]+',pc));assert len(constants.splitlines())==2
(OUT/'base-curl.rs').write_bytes((SOURCES/SNAP['exact_git_blobs']['crates/service-transport/curl.rs']['file']).read_bytes())
code='#![allow(dead_code)]\n#[path="base-curl.rs"] mod curl_transport;\n'
for role in ['gateway_get','prover_get']:
 variable='prover_url' if role=='gateway_get' else 'gw_url';actual=main if role=='gateway_get' else pv;join=f'format!(\"{{}}/attest\", {variable}.trim_end_matches(\'/\'))';assert join in actual
 code+='mod '+role+' { use crate::curl_transport;\n'+'\n'.join(gets)+'\npub(super) fn call('+variable+':&str,c:std::process::Command)->Result<serde_json::Value,String>{let url='+join+';http_get_json_command(&url,c)}\n}\n'
code+='mod prover_client { #[derive(Debug)] pub enum ProverClientError {Http(String),Unauthorized}\n'+constants+'\n'+'\n'.join(post)+'\n}\n'
code+='''fn main(){let a:Vec<String>=std::env::args().collect();assert_eq!(a.len(),4);let mut c=std::process::Command::new(&a[3]);for key in ["http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]{c.env_remove(key);}c.env("NO_PROXY","*").env("no_proxy","*");let result=match a[1].as_str(){"post"=>{let body="x".repeat(160*1024);match prover_client::http_post_command(&a[2],&body,5,Some("synthetic-bearer"),c){Ok(s)=>serde_json::json!({"kind":"OK","json_parser_accepted":serde_json::from_str::<serde_json::Value>(&s).is_ok(),"body":s}),Err(e)=>serde_json::json!({"kind":"ERROR","error":format!("{:?}",e)})}},"gateway-get"=>match gateway_get::call(&a[2],c){Ok(v)=>serde_json::json!({"kind":"OK","value":v}),Err(e)=>serde_json::json!({"kind":"ERROR","error":e})},"prover-get"=>match prover_get::call(&a[2],c){Ok(v)=>serde_json::json!({"kind":"OK","value":v}),Err(e)=>serde_json::json!({"kind":"ERROR","error":e})},_=>panic!("unknown owned mode")};println!("{}",result);}
'''
with (OUT/'probe.rs').open('x') as f:f.write(code)
rustc=subprocess.check_output(['rustup','which','--toolchain','1.99.0','rustc'],text=True).strip();curl=shutil.which('curl');assert curl
rlibs=sorted((ROOT/'target/debug/deps').glob('libserde_json-*.rlib'),key=lambda p:p.stat().st_mtime,reverse=True);assert rlibs
command=[rustc,'--edition=2021','--crate-name','owned_service_base_before',str(OUT/'probe.rs'),'-L','dependency='+str(ROOT/'target/debug/deps'),'--extern','serde_json='+str(rlibs[0]),'-o',str(OUT/'probe')]
start=time.monotonic();c=subprocess.run(command,capture_output=True,timeout=30);(OUT/'compile.stdout.log').write_bytes(c.stdout);(OUT/'compile.stderr.log').write_bytes(c.stderr)
compile_record={'command':command,'exit_code':c.returncode,'seconds':time.monotonic()-start,'source_sha256':sha(code.encode()),'stderr_sha256':sha(c.stderr),'stdout_sha256':sha(c.stdout),'extracted_function_sha256':{n:sha(function(main,n).encode()) for n in ['http_get_json','http_get_json_command']},'post_function_sha256':{n:sha(function(pc,n).encode()) for n in ['prove_curl_args','split_status','http_post','http_post_command']},'both_GET_bodies_byte_identical':True,'serde_rlib_sha256':sha(rlibs[0].read_bytes())}
(OUT/'compile.json').write_text(json.dumps(compile_record,indent=2)+'\n');assert c.returncode==0,c.stderr.decode()
version=subprocess.check_output([curl,'--version'],text=True);results={}
def execute(label,mode,url):
 started=time.monotonic();r=subprocess.run([str(OUT/'probe'),mode,url,curl],capture_output=True,timeout=15);(OUT/(label+'.stdout.log')).write_bytes(r.stdout);(OUT/(label+'.stderr.log')).write_bytes(r.stderr);assert r.returncode==0
 return {'exit_code':r.returncode,'seconds':time.monotonic()-started,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),'returned':json.loads(r.stdout)}
def request_case(label,suffix,mode):
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(2);listener.settimeout(.1);stop=threading.Event();requests=[];errors=[]
 def serve():
  try:
   deadline=time.monotonic()+10
   while len(requests)<1:
    try:conn,peer=listener.accept()
    except socket.timeout:
     if stop.is_set():break
     assert time.monotonic()<deadline;continue
    assert peer[0]=='127.0.0.1'
    with conn:
     conn.setblocking(True);conn.settimeout(3);data=b''
     while b'\r\n\r\n' not in data:
      chunk=conn.recv(8192);assert chunk;data+=chunk;assert len(data)<256*1024
     head,body=data.split(b'\r\n\r\n',1);length=int(next((line.split(b':',1)[1].strip() for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')),b'0'));assert length==(160*1024 if mode=='post' else 0)
     while len(body)<length:
      chunk=conn.recv(min(8192,length-len(body)));assert chunk;body+=chunk
     assert body==(b'x'*(160*1024) if mode=='post' else b'');assert mode!='post' or b'Authorization: Bearer synthetic-bearer' in head
     index=len(requests);status=200;payload=json.dumps({'owned_fixture':index+1},separators=(',',':')).encode();conn.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n'.encode()+payload);conn.shutdown(socket.SHUT_WR)
     try:conn.recv(1)
     except (socket.timeout,ConnectionResetError):pass
     wire=head+b'\r\n\r\n'+body;(OUT/f'{label}.request-{index}.bin').write_bytes(wire);requests.append({'target':head.split(b'\r\n')[0].decode(),'body_bytes':len(body),'body_sha256':sha(body),'wire_sha256':sha(wire),'response_status':status})
  except BaseException as e:errors.append(type(e).__name__+': '+str(e))
  finally:listener.close()
 thread=threading.Thread(target=serve);thread.start();url=f'http://127.0.0.1:{listener.getsockname()[1]}'+suffix
 try:r=execute(label,mode,url)
 finally:stop.set();thread.join(timeout=5)
 assert not thread.is_alive() and not errors,errors;r['requests']=requests;r['actual_request_count']=len(requests);return r
for mode in ['post','gateway-get','prover-get']:
 endpoint='prove' if mode=='post' else 'attest';method='POST' if mode=='post' else 'GET'
 for label,suffix,target in [('control','/base/',f'{method} /base/{endpoint} HTTP/1.1'),('query','/base?x=1',f'{method} /base?x=1/{endpoint} HTTP/1.1'),('fragment','/base#note',f'{method} /base HTTP/1.1'),('empty-query','/base?',f'{method} /base?/{endpoint} HTTP/1.1')]:
  key=mode+'-'+label;results[key]=request_case(key,suffix,mode);assert results[key]['actual_request_count']==1;assert results[key]['requests'][0]['target']==target;assert results[key]['returned']['kind']=='OK';assert mode!='post' or results[key]['returned']['json_parser_accepted']
sys.path.insert(0,str(ROOT/'scripts/local-verification'));import candidate_identity_manifest as identity
after=identity.source_inventory(ROOT);extra={'scripts/tee-capture/Cargo.lock':sha((ROOT/'scripts/tee-capture/Cargo.lock').read_bytes())}
record={'schema':'arcora-service-base-exact-before-owned-reproducer/v1','captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base':SNAP['base'],'passed_reproduction_assertions':True,'source_snapshot_sha256':sha((OUT/'base-snapshot.json').read_bytes()),'compile':compile_record,'curl_executable_selected_from_trusted_PATH':curl,'curl_version':version,'results':results,'public_map_before':SNAP['public_map_before'],'public_map_after':{'files':len(after),'sha256':sha(identity.canonical(after)),'files_sha256':after},'public_map_equal':after==SNAP['public_map_before']['files_sha256'],'extra_public_before':SNAP['public_extra_before'],'extra_public_after':extra,'baseline_archives_unchanged':all(sha((SOURCES/m['file']).read_bytes())==m['sha256'] for m in SNAP['exact_git_blobs'].values()),'scope':'Exact archived BASE1caae328 low-level POST and both identical GET functions compiled with real serde_json/nativecurl. The two GET wrappers mechanically reuse the exact known /attest caller join expression then invoke the GET helper; whole handshake/boot functions are NOT invoked. Four owned loopback base cases perrole, one actual request each. Wrong route fixture200/JSON is low-level only, no real service/proof/attestation acceptance. Trusted operator publicURLs/body/bearer only, no privateenv/config/credentials/backend. Aftermap may contain concurrent parent changes; archivedBASE blobs are still hash-checked. All writes only this new ignored recovery directory.'}
(OUT/'reproducer.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result_sha256':sha((OUT/'reproducer.json').read_bytes()),'compile_exit':c.returncode,'source_map_equal':record['public_map_equal'],'source_sha256':record['public_map_after']['sha256'],'actual_targets':{k:v['requests'][0]['target'] for k,v in results.items()},'actual_counts':{k:v['actual_request_count'] for k,v in results.items()}},indent=2))
