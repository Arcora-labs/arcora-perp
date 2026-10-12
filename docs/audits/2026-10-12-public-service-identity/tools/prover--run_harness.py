import datetime,hashlib,json,os,subprocess,time
from pathlib import Path
repo=Path.cwd();out=repo/'target/candidate-service-validation-20261012/prover'
cargo=subprocess.check_output(['rustup','which','--toolchain','1.99.0','cargo'],text=True).strip();bin=Path(cargo).parent
env=dict(os.environ);env.update(PATH=str(out/'python-bin')+':'+str(bin)+':'+env['PATH'],CARGO_TARGET_DIR=str(out/'harness-target'),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',PYTHONDONTWRITEBYTECODE='1')
files=list(json.loads((out/'owned-source-freeze.json').read_bytes())['source_sha256'])+['crates/service-identity/public.rs','crates/service-identity/build_support.rs','scripts/local-verification/service_build_identity.py','scripts/local-verification/candidate_identity_manifest.py']
def fp():return {x:hashlib.sha256((repo/x).read_bytes()).hexdigest() for x in files}
versions={}
for name,cmd in [('cargo',[cargo,'--version']),('rustc',['rustc','--version']),('clippy',[str(bin/'cargo-clippy'),'--version']),('python',['python3','--version'])]:
 r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);assert r.returncode==0;versions[name]=(r.stdout+r.stderr).decode().strip()
(out/'harness-toolchain.json').write_text(json.dumps({'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'versions':versions,'path_prefix':[str(out/'python-bin'),str(bin)]},indent=2)+'\n')
print('Toolchain '+json.dumps(versions),flush=True)
commands=[('harness-tests',[cargo,'test','--offline','--locked','--manifest-path','scripts/local-verification/service-identity-harness/Cargo.toml','--','--nocapture']),('harness-clippy',[cargo,'clippy','--offline','--locked','--all-targets','--manifest-path','scripts/local-verification/service-identity-harness/Cargo.toml','--','-D','warnings'])]
for name,cmd in commands:
 before=fp();start=time.monotonic();print('START '+name,flush=True)
 with (out/(name+'.stdout.log')).open('wb') as stdout,(out/(name+'.stderr.log')).open('wb') as stderr:r=subprocess.run(cmd,env=env,stdout=stdout,stderr=stderr)
 after=fp();record={'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':cmd,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'source_sha256_before':before,'source_sha256_after':after,'sources_unchanged':before==after,'stdout_sha256':hashlib.sha256((out/(name+'.stdout.log')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((out/(name+'.stderr.log')).read_bytes()).hexdigest(),'toolchain':versions,'scope':'Dependency-light harness imports exact production identity module/public envelope, injects committed reviewedELF fixture, tests owned loopback only. No SDK/backend boot/setup/proving or loaded-service attestation claim.'};(out/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n');print('END '+name+' '+json.dumps({'exit':r.returncode,'unchanged':before==after,'seconds':record['elapsed_seconds']}),flush=True)
 if r.returncode or before!=after:raise SystemExit(r.returncode or 2)
