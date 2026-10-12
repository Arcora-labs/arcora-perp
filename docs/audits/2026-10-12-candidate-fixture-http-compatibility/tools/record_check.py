import datetime, hashlib, json, os, subprocess, sys, time
from pathlib import Path
root = Path.cwd()
out = root / 'target/candidate-transport-validation-20261012/checks'
out.mkdir(exist_ok=True)
sys.path.insert(0, str(root/'scripts/local-verification'))
import candidate_identity_manifest as identity
name = sys.argv[1]
commands = {
    'fixture-first': ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','test','--locked','-p','gateway','--bin','gateway','candidate_fixture_transport_tests','--','--nocapture'],
    'gateway-final': ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','test','--locked','-p','gateway','--bin','gateway'],
    'workspace-clippy': ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','clippy','--workspace','--all-targets','--locked','--','-D','warnings'],
    'workspace-format': ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','fmt','--all','--check'],
    'harness-format': ['/Users/huseyinarslan/.cargo/bin/cargo','+1.99.0','fmt','--manifest-path','scripts/local-verification/service-identity-harness/Cargo.toml','--check'],
}
patterns = {
    'new-python-final': ['test_service_build_identity.py','test_service_identity_preflight.py'],
    'neighbors-final': ['test_candidate_identity_manifest.py','test_candidate_target_observer.py','test_release_manifest.py','test_operator_policy.py','test_read_deployment.py','test_check_sp1_release.py','test_verify_clock_proof.py','test_repository_policy.py'],
}
pattern_name = 'new-python-final' if name.startswith('new-python') else name
if pattern_name in patterns:
    command = ['/opt/homebrew/bin/python3.12', '-c', "import sys,unittest; suite=unittest.TestSuite(); loader=unittest.TestLoader(); " + ''.join("suite.addTests(loader.discover('scripts/local-verification',pattern="+repr(p)+")); " for p in patterns[pattern_name])+"r=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not r.wasSuccessful())"]
else:
    command = commands['fixture-first'] if name.startswith('fixture-') else commands['workspace-clippy'] if name.startswith('workspace-clippy') else commands['workspace-format'] if name.startswith('workspace-format') else commands[name]
before = identity.source_inventory(root)
os.environ['PATH'] = str(root/'target/candidate-service-validation-20261012/prover/python-bin')+':'+os.environ['PATH']
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['RUST_TEST_THREADS'] = '2'
start = time.monotonic()
with (out/(name+'.stdout.log')).open('xb') as stdout, (out/(name+'.stderr.log')).open('xb') as stderr:
    result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=1200)
after = identity.source_inventory(root)
receipt = {'schema':'arcora-service-identity-check-v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-start,'source_before':before,'source_after':after,'source_files':len(after),'source_inventory_unchanged':before==after,'source_map_sha256':identity.digest(identity.canonical(after)),'stdout_sha256':hashlib.sha256((out/(name+'.stdout.log')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((out/(name+'.stderr.log')).read_bytes()).hexdigest(),'production_release':'HOLD'}
with (out/(name+'.json')).open('x') as f:f.write(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ('exit_code','elapsed_seconds','source_files','source_inventory_unchanged','source_map_sha256')}))
raise SystemExit(result.returncode)
