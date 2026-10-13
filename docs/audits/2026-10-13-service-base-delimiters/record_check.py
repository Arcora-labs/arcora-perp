import datetime, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
root=Path.cwd()
out=root/'target/service-base-validation-20261013'
sys.path.insert(0,str(root/'scripts/local-verification'))
import candidate_identity_manifest as identity
name=sys.argv[1]
assert re.fullmatch(r'[a-z0-9-]+',name)
args=sys.argv[2:]
if args[0]=='--':args=args[1:]
freeze=json.loads((out/'source-freeze-final.json').read_bytes())
def inventory():return identity.source_inventory(root)
before=inventory();assert before==freeze['source_files']
task=out/name;task.mkdir()
env=dict(os.environ)
flags={'CARGO_BUILD_JOBS':'2','RUST_TEST_THREADS':'2','PYTHONDONTWRITEBYTECODE':'1',
       'PATH':str(out/'python-bin')+':/Users/huseyinarslan/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin:'+os.environ['PATH'],
       'RUSTC':'/Users/huseyinarslan/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin/rustc',
       'RUSTUP_TOOLCHAIN':'1.99.0'}
env.update(flags)
start=time.monotonic();now=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (task/'stdout.log').open('xb') as stdout,(task/'stderr.log').open('xb') as stderr:
    result=subprocess.run(args,env=env,stdout=stdout,stderr=stderr)
after=inventory()
stdout=(task/'stdout.log').read_bytes();stderr=(task/'stderr.log').read_bytes()
summaries=re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', (stdout+stderr).decode(errors='replace'))
record={'schema':'arcora-service-base-command/v1','started_utc':now,'command':args,'cwd':str(root),'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-start,'source_sha256_before':before,'source_sha256_after':after,'source_sha256':freeze['source_sha256'],'sources_unchanged':before==after,'test_summaries':[{'state':s,'passed':int(p),'failed':int(f),'ignored':int(i)} for s,p,f,i in summaries],'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),'environment_override':flags,'production_release':'HOLD'}
with (task/'verification.json').open('x') as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({'name':name,'exit_code':result.returncode,'sources_unchanged':before==after,'seconds':record['elapsed_seconds'],'tests':record['test_summaries']}),flush=True)
if result.returncode:
    print(stderr.decode(errors='replace')[-5000:],flush=True)
    print(stdout.decode(errors='replace')[-2500:],flush=True)
if result.returncode or before!=after:raise SystemExit(result.returncode or 2)
