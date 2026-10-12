from pathlib import Path
import os,json,hashlib,subprocess,datetime,time,signal,sys
root=Path(__file__).resolve().parents[3];repair=root/'target/curl-bounds-validation-20261012/dependency-repair';kind=sys.argv[1];assert kind in ['check','audit']
p=repair/('tee-check' if kind=='check' else 'tee-audit')
if kind=='audit':p.mkdir(mode=0o700)
sha=lambda q:hashlib.sha256(q.read_bytes()).hexdigest();freeze=root/'target/curl-bounds-validation-20261012/source-freeze-final.json';f=json.loads(freeze.read_text());public=lambda:{n:sha(root/n) for n in f['source_files']}
current=public();assert current==f['source_files'];lock=root/'scripts/tee-capture/Cargo.lock';manifest=root/'scripts/tee-capture/Cargo.toml';before={'covered_source_files':len(current),'covered_source_sha256':f['source_sha256'],'source_files_sha256':current,'tee_lock_sha256':sha(lock),'tee_manifest_sha256':sha(manifest),'root_Cargo_lock_sha256':sha(root/'Cargo.lock'),'root_Cargo_toml_sha256':sha(root/'Cargo.toml')}
actualbin=Path('/Users/huseyinarslan/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin');cargo=actualbin/'cargo';rustc=actualbin/'rustc';home=repair/'tee-check/home';cache=repair/'tee-check/cargo-home'
env={'HOME':str(home),'CARGO_HOME':str(cache),'PATH':str(actualbin)+':/Users/huseyinarslan/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin','RUSTC':str(rustc),'RUSTUP_TOOLCHAIN':'1.99.0','CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(repair/'tee-check/cargo-target'),'PYTHONDONTWRITEBYTECODE':'1'}
args=[str(cargo),'check','--locked','--manifest-path','scripts/tee-capture/Cargo.toml'] if kind=='check' else [str(cargo),'audit','--deny','unsound','--file','scripts/tee-capture/Cargo.lock','--json','--db',str(p/'advisory-db')]
start=time.monotonic();started=datetime.datetime.now(datetime.timezone.utc).isoformat();timed=False
with (p/'stdout.log').open('xb') as stdout,(p/'stderr.log').open('xb') as stderr:
 proc=subprocess.Popen(args,cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
 try:code=proc.wait(timeout=1200)
 except subprocess.TimeoutExpired:timed=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
elapsed=time.monotonic()-start;after=public();aftercut={'covered_source_files':len(after),'covered_source_sha256':f['source_sha256'],'source_files_sha256':after,'tee_lock_sha256':sha(lock),'tee_manifest_sha256':sha(manifest),'root_Cargo_lock_sha256':sha(root/'Cargo.lock'),'root_Cargo_toml_sha256':sha(root/'Cargo.toml')}
receipt={'schema':'arcora-curl-dependency-repair-validation/v1','kind':kind,'started_at':started,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':args,'cwd':str(root),'exit_code':code,'timed_out':timed,'elapsed_seconds':elapsed,'source_before':before,'source_after':aftercut,'source_and_lock_unchanged':before==aftercut,'stdout_sha256':sha(p/'stdout.log'),'stderr_sha256':sha(p/'stderr.log'),'cargo_binary':str(cargo),'rustc_binary':str(rustc),'environment_scope':'Explicit public build environment; own HOME/CARGO_HOME/target, reuse only public cachedregistry. No ambient Cargo configuration or credential files read. No capture.sh/bin/service/backend/proving executed.','environment_overrides':env,'runner_sha256':sha(Path(__file__)),'scope':'Actual excluded tee tool compilation only' if kind=='check' else 'Current RustSec advisory DB audit of the excluded tee lock, no ignores','production_release':'HOLD'}
if kind=='audit':
 try:
  data=json.loads((p/'stdout.log').read_text());receipt['audit_database']=data.get('database');receipt['vulnerabilities']={'found':data['vulnerabilities']['found'],'count':data['vulnerabilities']['count'],'ids':[v['advisory']['id'] for v in data['vulnerabilities']['list']]};receipt['warnings']={n:len(v) for n,v in data.get('warnings',{}).items()}
 except (ValueError,KeyError):receipt['audit_json_parsed']=False
with (p/'receipt.json').open('x') as stream:json.dump(receipt,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
print(json.dumps({'kind':kind,'receipt':str(p/'receipt.json'),'receipt_sha256':sha(p/'receipt.json'),'exit_code':code,'elapsed_seconds':elapsed,'source_and_lock_unchanged':before==aftercut,'tee_lock_sha256':before['tee_lock_sha256']}),flush=True)
sys.exit(0 if code==0 and before==aftercut else 1)
