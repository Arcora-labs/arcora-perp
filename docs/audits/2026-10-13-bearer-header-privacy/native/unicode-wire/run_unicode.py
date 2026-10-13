import datetime,hashlib,json,os,shlex,shutil,socket,stat,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path.cwd();OUT=ROOT/'target/bearer-argv-validation-20261013/native/unicode-wire'
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,b):
 with p.open('xb') as f:f.write(b)
rc=subprocess.check_output(['rustup','which','--toolchain','1.99.0','rustc'],text=True).strip();curl=shutil.which('curl');assert curl;deps=ROOT/'target/debug/deps';serde=max(deps.glob('libserde_json-*.rlib'),key=lambda p:p.stat().st_mtime)
cmd=[rc,'--edition=2021','--crate-name','owned_native_bearer',str(OUT/'probe.rs'),'-L','dependency='+str(deps),'--extern','serde_json='+str(serde),'-o',str(OUT/'probe')];start=time.monotonic();compiled=subprocess.run(cmd,capture_output=True,timeout=30);save(OUT/'compile.stdout.log',compiled.stdout);save(OUT/'compile.stderr.log',compiled.stderr);save(OUT/'compile.json',(json.dumps({'command':cmd,'exit_code':compiled.returncode,'seconds':time.monotonic()-start,'source_sha256':sha((OUT/'probe.rs').read_bytes()),'serde_rlib_sha256':sha(serde.read_bytes()),'stdout_sha256':sha(compiled.stdout),'stderr_sha256':sha(compiled.stderr)},indent=2)+'\n').encode());assert compiled.returncode==0,compiled.stderr.decode()
body='{"owned":"public"}';assert len(body.encode())==18
results={};headers=OUT/'headers-root';headers.mkdir(mode=0o700)

def case(label,token,status=200,kind='http',timeout=4,temp_group=None,body_limit=None,url_tail='/base/'):
 temp= headers/(temp_group or label)
 if not temp.exists():temp.mkdir(mode=0o700)
 assert not list(temp.iterdir());listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(.1);port=listener.getsockname()[1];stop=threading.Event();got=threading.Event();release=threading.Event();errors=[];requests=[]
 def serve():
  try:
   until=time.monotonic()+12
   while not stop.is_set():
    try:conn,peer=listener.accept();break
    except socket.timeout:assert time.monotonic()<until
   else:return
   assert peer[0]=='127.0.0.1'
   with conn:
    conn.setblocking(True);conn.settimeout(3);data=b''
    while b'\r\n\r\n' not in data:
     chunk=conn.recv(8192);assert chunk;data+=chunk;assert len(data)<256*1024
    head,payload=data.split(b'\r\n\r\n',1);length=int(next(line.split(b':',1)[1].strip() for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')));assert length==len(body.encode())
    while len(payload)<length:
     chunk=conn.recv(min(8192,length-len(payload)));assert chunk;payload+=chunk
    assert payload==body.encode();assert head.split(b'\r\n')[0]==b'POST /base/prove HTTP/1.1';auth=[line for line in head.split(b'\r\n') if line.lower().startswith(b'authorization:')]
    if token is None:assert not auth
    else:assert auth==[('Authorization: Bearer '+token).encode()]
    wire=head+b'\r\n\r\n'+payload;save(OUT/(label+'.request.bin'),wire);requests.append({'target':'POST /base/prove HTTP/1.1','body_bytes':length,'body_sha256':sha(payload),'wire_sha256':sha(wire),'authorization_count':len(auth),'public_token_exact':token is None or auth[0]==('Authorization: Bearer '+token).encode(),'scripted_status':status});got.set();assert release.wait(12)
    if kind=='curl-timeout':return
    reply=b'{"owned_fixture":true}';conn.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: {len(reply)}\r\nConnection: close\r\n\r\n'.encode()+reply);conn.shutdown(socket.SHUT_WR)
    try:conn.recv(1)
    except (socket.timeout,ConnectionResetError):pass
  except BaseException as e:errors.append(type(e).__name__+': '+str(e));got.set()
  finally:listener.close()
 thread=threading.Thread(target=serve);thread.start();pidfile=OUT/(label+'.owned-pid');argvfile=OUT/(label+'.argv.bin');wrapper=OUT/(label+'.wrapper.sh')
 script='#!/bin/sh\nprintf "%s\\n" "$$" > '+shlex.quote(str(pidfile))+'\nprintf "%s\\0" "$@" > '+shlex.quote(str(argvfile))+'\n'
 script+=('exec '+shlex.quote('/opt/homebrew/bin/python3.12')+" -c 'import time;time.sleep(30)' \"$@\"\n") if kind=='supervisor-hang' else ('exec '+shlex.quote(curl)+' "$@"\n')
 save(wrapper,script.encode());wrapper.chmod(0o700);command=str(OUT/'missing-owned-executable') if kind=='spawn-fail' else str(wrapper)
 inputfile=OUT/(label+'.input.json');spec={'url':f'http://127.0.0.1:{port}'+url_tail,'body':body,'token':token,'timeout_secs':timeout,'body_limit':len(body.encode()) if body_limit is None else body_limit,'command':command};save(inputfile,(json.dumps(spec,ensure_ascii=False)+'\n').encode())
 start=time.monotonic();p=subprocess.Popen([str(OUT/'probe'),str(inputfile)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','TMPDIR':str(temp)})
 metadata=None;ps_record=None;args=None;header_path=None;directory=None
 expect_started=kind not in ['malformed','spawn-fail','precheck']
 try:
  if expect_started:
   if kind=='supervisor-hang':
    until=time.monotonic()+3
    while not argvfile.exists():assert p.poll() is None and time.monotonic()<until;time.sleep(.01)
   else:assert got.wait(6) and not errors,errors
   assert pidfile.exists() and argvfile.exists();pid=int(pidfile.read_text());args=[x.decode() for x in argvfile.read_bytes().split(b'\0') if x];assert token is None or all(token not in arg for arg in args)
   header_args=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='-H' and args[i+1].startswith('@')];assert len(header_args)==(0 if token is None else 1)
   if token is not None:
    header_path=Path(header_args[0][1:]);assert header_path.resolve().is_relative_to(temp.resolve());directory=header_path.parent;fm=header_path.lstat();dm=directory.lstat();assert stat.S_ISREG(fm.st_mode) and not header_path.is_symlink() and stat.S_IMODE(fm.st_mode)==0o600 and fm.st_nlink==1 and fm.st_uid==os.getuid();assert stat.S_ISDIR(dm.st_mode) and stat.S_IMODE(dm.st_mode)==0o700 and dm.st_uid==os.getuid()
    metadata={'known_header_path':str(header_path),'private_directory':str(directory),'file_mode':'0600','directory_mode':'0700','regular_file':True,'owner_matches':True,'nlink':fm.st_nlink,'file_exists_during_held_response_or_owned_hang':True}
   else:assert not list(temp.iterdir())
   ps_cmd=['/bin/ps','-ww','-p',str(pid),'-o','pid=,ppid=,command='];ps=subprocess.run(ps_cmd,capture_output=True,timeout=2);save(OUT/(label+'.ps.stdout.log'),ps.stdout);save(OUT/(label+'.ps.stderr.log'),ps.stderr);assert ps.returncode==0;fields=ps.stdout.decode().strip().split(None,2);assert int(fields[0])==pid and int(fields[1])==p.pid;assert token is None or token not in fields[2]
   ps_record={'command':ps_cmd,'known_owned_PID':pid,'PPID_matches_probe':True,'synthetic_token_absent':token is None or token not in fields[2],'observed_program':'ownedPythonhang' if kind=='supervisor-hang' else 'nativecurl','stdout_sha256':sha(ps.stdout),'stderr_sha256':sha(ps.stderr)}
  if kind not in ['curl-timeout','supervisor-hang']:release.set()
  stdout,stderr=p.communicate(timeout=9)
 finally:
  release.set();stop.set();thread.join(timeout=4)
 save(OUT/(label+'.stdout.log'),stdout);save(OUT/(label+'.stderr.log'),stderr);assert p.returncode==0 and not thread.is_alive() and not errors,errors
 returned=json.loads(stdout)['returned'];assert not list(temp.iterdir());assert header_path is None or not header_path.exists();assert directory is None or not directory.exists()
 if kind=='malformed':assert returned=={'kind':'ERROR','error':'Http("invalid HTTP bearer header")'} and not pidfile.exists() and not requests and token not in returned['error']
 elif kind=='spawn-fail':assert returned=={'kind':'ERROR','error':'Http("HTTP transport could not start")'} and not pidfile.exists() and not requests
 elif kind=='supervisor-hang':assert returned=={'kind':'ERROR','error':'Http("HTTP transport supervisor deadline exceeded")'} and not requests
 elif kind=='curl-timeout':assert returned['kind']=='ERROR' and 'exit status: 28' in returned['error'] and len(requests)==1
 elif kind=='precheck':assert returned['kind']=='ERROR' and not pidfile.exists() and not requests
 elif status==401:assert returned=={'kind':'ERROR','error':'Unauthorized'} and len(requests)==1
 elif status==500:assert returned=={'kind':'ERROR','error':'Http("prover /prove HTTP 500")'} and len(requests)==1
 else:assert returned['kind']=='OK' and returned['JSON_accepted'] and len(requests)==1
 return {'seconds':time.monotonic()-start,'kind':kind,'status':status,'public_token_label':token,'returned':returned,'child_marker_exists':pidfile.exists(),'HTTP_requests':requests,'HTTP_request_count':len(requests),'observed_metadata':metadata,'known_owned_ps':ps_record,'header_path_removed_after_return':header_path is None or not header_path.exists(),'private_directory_removed_after_return':directory is None or not directory.exists(),'owned_temp_root_empty_after_return':True,'owned_TMPDIR':str(temp),'input_spec_sha256':sha(inputfile.read_bytes()),'wrapper_sha256':sha(wrapper.read_bytes()),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'exact_args_sha256':sha(argvfile.read_bytes()) if argvfile.exists() else None,'spawnfail_scope':'Filepath was not observed in-flight; post-erroremptytree plus exact sourceowner-before-run ordering, not heldfile observation.' if kind=='spawn-fail' else None}

results['unicode-positive']=case('unicode-positive','PUBLIC-synthetic / + = ü',200,'http',4,None,None,'/base/')
sys.path.insert(0,str(ROOT/'scripts/local-verification'));import candidate_identity_manifest as identity;before=json.loads((OUT/'source-snapshot.json').read_bytes());after=identity.source_inventory(ROOT);assert before['source_files_sha256']==after
record={'schema':'arcora-bearer-native-production-source-observation/v1','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,'source_count':len(after),'source_sha256':sha(identity.canonical(after)),'source_before_after_equal':True,'source_snapshot_sha256':sha((OUT/'source-snapshot.json').read_bytes()),'native_curl':curl,'curl_version':subprocess.check_output([curl,'--version'],text=True),'cases':results,'case_count':len(results),'HTTP_request_total':sum(v['HTTP_request_count'] for v in results.values()),'additional_positive_scope':'PUBLIC synthetic spaces/plus/equal/UTF8 header bytes, transport fixture only not realprover admission/tokenmint;','scope':'Exact production funcs/header module compiled normal nativebinary; publicsynthetic tokens/body only. KnownOWNED PID/header path inspection only; private TMPDIR set ONLY in ownprobeprocess, no ambientsecret/env/config reads. SameUID/root/SIGKILL residualscope remains. SuccessNone200 is only fixture transport control, no realprover/authacceptance. OwnPythonhang tests directchild supervisor, not curl timeout. No backend/quote/setup/prove/GPU or source/old/outside changes.'}
save(OUT/'result.json',(json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'passed':True,'result_sha256':sha((OUT/'result.json').read_bytes()),'cases':len(results),'actual_HTTP_requests':record['HTTP_request_total'],'source_count':len(after),'source_sha256':record['source_sha256'],'all_headers_cleaned_after_return':True,'unicode_public_header_bytes_exact':True},indent=2))
