import datetime,hashlib,json,os,re,subprocess,time
from pathlib import Path
repo=Path.cwd();out=repo/'target/candidate-service-validation-20261012/prover';task=out/'actual-typecheck';cargo=subprocess.check_output(['rustup','which','--toolchain','1.99.0','cargo'],text=True).strip();bin=Path(cargo).parent
flags={'PATH':str(out/'python-bin')+':'+str(bin)+':'+str(task/'tools')+':'+os.environ['PATH'],'RUSTC':str(bin/'rustc'),'RUSTUP_TOOLCHAIN':'1.99.0','CARGO_HOME':str(task/'cargo-home'),'CARGO_TARGET_DIR':str(task/'cargo-target'),'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_NET_OFFLINE':'true','SP1_SKIP_PROGRAM_BUILD':'true','SP1_CORE_RUNNER_OVERRIDE_BINARY':str(task/'tools/sp1-native-runner-existing'),'PROTOC':str(task/'tools/protoc'),'PROTOC_INCLUDE':str(task/'tools/include'),'PYTHONDONTWRITEBYTECODE':'1'}
env=dict(os.environ);env.update(flags)
files=list(json.loads((out/'owned-source-freeze.json').read_bytes())['source_sha256'])+['Cargo.toml','Cargo.lock','crates/prover-service/Cargo.toml','crates/prover-service/Cargo.lock','crates/prover-service/build.rs','crates/prover-service/src/admission.rs','crates/prover-service/src/shutdown_tests.rs','crates/service-identity/public.rs','crates/service-identity/build_support.rs','scripts/local-verification/service_build_identity.py','scripts/local-verification/candidate_identity_manifest.py','crates/sp1-guest/Cargo.toml','crates/sp1-guest/Cargo.lock','crates/sp1-guest/src/main.rs','contracts/integration/fixtures/clock-v2-verified/guest.elf','contracts/integration/fixtures/clock-v2-verified/program-vkey.bin']
# Bind all reviewed guest/core pins without modifying them.
file=repo/'contracts/integration/fixtures/clock-v2-verified/proof-evidence.json';j=json.loads(file.read_bytes());files+=list(j.get('guest_sources_sha256',j.get('guest_source_sha256',{})))
files=list(dict.fromkeys(files))
def fp():return {x:hashlib.sha256((repo/x).read_bytes()).hexdigest() for x in files}
versions={}
for name,cmd in [('cargo',[cargo,'--version']),('rustc',[str(bin/'rustc'),'--version']),('python',['python3','--version']),('protoc',[str(task/'tools/protoc'),'--version'])]:
 r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);assert r.returncode==0;versions[name]=(r.stdout+r.stderr).decode().strip()
before=fp();cmd=[cargo,'check','--offline','--locked','--manifest-path','crates/prover-service/Cargo.toml','--bin','prover-service'];start=time.monotonic();print('START actual prover typecheck '+json.dumps(versions),flush=True)
with (out/'actual-typecheck.stdout.log').open('wb') as stdout,(out/'actual-typecheck.stderr.log').open('wb') as stderr:r=subprocess.run(cmd,env=env,stdout=stdout,stderr=stderr)
after=fp()
def pkgs(raw):
 d={}
 for part in raw.split('[[package]]')[1:]:
  n=re.search(r'^name = "([^"]+)"$',part,re.M).group(1);v=re.search(r'^version = "([^"]+)"$',part,re.M).group(1);d.setdefault(n,[]).append(v)
 return d
base=pkgs((repo/'Cargo.lock').read_text());h=pkgs((repo/'scripts/local-verification/service-identity-harness/Cargo.lock').read_text());outside={n:vs for n,vs in h.items() if n!='arcora-service-identity-harness' and any(v not in base.get(n,[]) for v in vs)}
record={'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':cmd,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'env_whitelist':flags,'toolchain':versions,'source_sha256_before':before,'source_sha256_after':after,'sources_unchanged':before==after,'harness_dependency_versions_outside_root':outside,'stdout_sha256':hashlib.sha256((out/'actual-typecheck.stdout.log').read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((out/'actual-typecheck.stderr.log').read_bytes()).hexdigest(),'scope':'Actual prover-service production main/backend source typecheck only. Existing committed ELF copied to owned skipped-build path; SDK native helper/protoc copied to owned paths; owned CARGO_HOME cloned registry, no global SDK/cache or source/guest mutation. No backend boot/setup/key derivation/prove/handshake/service or loaded-service acceptance claim.'};(out/'actual-typecheck.json').write_text(json.dumps(record,indent=2)+'\n');print('END actual prover typecheck '+json.dumps({'exit':r.returncode,'unchanged':before==after,'seconds':record['elapsed_seconds'],'harness_outside':outside}),flush=True)
if r.returncode or before!=after or outside:raise SystemExit(r.returncode or 2)
