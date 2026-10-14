from pathlib import Path
from datetime import datetime, timezone
from hashlib import sha256
import subprocess,sys,json,os,time
repo=Path(__file__).resolve().parents[2]
out=Path(__file__).resolve().parent
name=sys.argv[1];command=sys.argv[2:]
assert name.isidentifier() and command
folder=out/'local'/name;folder.mkdir(parents=True,exist_ok=False)
paths=['crates/sequencer/src/lib.rs','crates/gateway/src/prover_client.rs','crates/gateway/src/prover_client/window_ownership_tests.rs']
inputs={p:sha256((repo/p).read_bytes()).hexdigest() for p in paths}
env=os.environ.copy();rust='/Users/huseyinarslan/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin'
env['RUSTC']=rust+'/rustc';env['PATH']=rust+':/opt/homebrew/bin:'+env.get('PATH','');env['RUST_TEST_THREADS']='2'
start=time.monotonic();stamp=datetime.now(timezone.utc).isoformat()
with (folder/'stdout.log').open('xb') as stdout,(folder/'stderr.log').open('xb') as stderr:
 result=subprocess.run(command,cwd=repo,env=env,stdout=stdout,stderr=stderr)
files={p.name:{'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()} for p in folder.iterdir()}
assert inputs=={p:sha256((repo/p).read_bytes()).hexdigest() for p in paths},'Source changed during execution'
record={'schema':'arcora-seal-window-owned-local-check/v1','started_at':stamp,'completed_at':datetime.now(timezone.utc).isoformat(),'cwd':str(repo),'command':command,'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-start,'source_files':inputs,'runtime':{'cargo':rust+'/cargo','rustc':rust+'/rustc','rust_test_threads':2},'files':files,'scope':'Actual owned subprocess; no GPU/proof/production process; rawstdout/stderr preserved'}
(folder/'result.json').write_text(json.dumps(record,sort_keys=True,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(record,ensure_ascii=False));sys.exit(result.returncode)
