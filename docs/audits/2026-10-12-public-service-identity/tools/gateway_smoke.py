import datetime, hashlib, json, os, subprocess, sys, time
from pathlib import Path
root = Path.cwd()
out = root / 'target/candidate-service-validation-20261012/gateway'
out.mkdir(exist_ok=True)
paths = ['crates/gateway/src/main.rs','crates/gateway/src/l1.rs','crates/gateway/src/public_identity.rs','crates/gateway/src/public_identity_tests.rs','crates/service-identity/public.rs','crates/service-identity/build_support.rs','crates/gateway/build.rs','crates/gateway/Cargo.toml','Cargo.toml','Cargo.lock','scripts/local-verification/service_build_identity.py']
def hashes():
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in paths}
before = hashes()
name = sys.argv[1] if len(sys.argv) > 1 else 'smoke'
os.environ['PATH'] = str(root/'target/candidate-service-validation-20261012/prover/python-bin') + ':' + os.environ['PATH']
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
command = ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','test','--locked','-p','gateway','public_identity','--','--nocapture']
start = time.monotonic()
with (out/(name+'.stdout.log')).open('xb') as stdout, (out/(name+'.stderr.log')).open('xb') as stderr:
    result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=600)
after = hashes()
receipt = {'schema':'arcora-service-identity-gateway-smoke-v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-start,'source_before':before,'source_after':after,'watched_sources_unchanged':before==after,'stdout_sha256':hashlib.sha256((out/(name+'.stdout.log')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((out/(name+'.stderr.log')).read_bytes()).hexdigest(),'production_release':'HOLD'}
with (out/(name+'.json')).open('x') as f:
    f.write(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
raise SystemExit(result.returncode)
