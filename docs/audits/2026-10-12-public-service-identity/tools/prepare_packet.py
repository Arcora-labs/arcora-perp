from pathlib import Path
import datetime,hashlib,json,shutil,subprocess
r=Path.cwd();src=r/'target/candidate-service-validation-20261012';dst=r/'docs/audits/2026-10-12-public-service-identity'
for n in ['receipts','logs','tools']: (dst/n).mkdir(exist_ok=True)
selected=[]
for f in src.iterdir():
 if f.is_file() and (f.suffix in {'.json','.log'} or f.name in {'record_check.py','gateway_smoke.py','prepare_packet.py'}):selected.append(f)
for n in ['checks','gateway','build','preflight','prover']:
 selected += [f for f in (src/n).iterdir() if f.is_file() and f.suffix in {'.json','.log','.py','.txt'}]
selected += [src/'build/own-source/service-build-identity.json',src/'build/own-source-current/service-build-identity.json']
selected += list((src/'prover/actual-typecheck/cargo-target/debug/build').glob('prover-service-*/out/service-build-identity.json'))
assert any(f.name=='preservation-root-final.json' for f in selected)
copy_map={}
for f in sorted(set(selected)):
 rel=f.relative_to(src).as_posix();name=rel.replace('/','--')
 sub='logs' if f.suffix=='.log' else 'tools' if f.suffix=='.py' else 'receipts'
 target=dst/sub/name
 assert not target.exists(),target
 shutil.copyfile(f,target)
 copy_map[target.relative_to(dst).as_posix()]={'original':f.relative_to(r).as_posix(),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size}
code='9c7347870d7212ec2ca66a92729ee5b433ca9efb';base='8f5e97bc690c1d9a6d796fdc3725526d283e077d'
paths=subprocess.check_output(['git','diff','--name-only',base,code],text=True).splitlines()
code_map={p:hashlib.sha256(subprocess.check_output(['git','show',code+':'+p])).hexdigest()for p in paths}
artifacts={f.relative_to(dst).as_posix():{'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size}for f in dst.rglob('*') if f.is_file()}
checks={}
for f in (src/'checks').glob('*.json'):
 o=json.loads(f.read_text());assert o.get('passed',o.get('exit_code')==0),f
 if 'source_inventory_unchanged'in o:assert o['source_inventory_unchanged']and o['source_files']==371 and o['source_map_sha256']=='7fd564c8bf0ec2bd3434635a06ff046e9faec759996c78a2c6db47ed85b5619d'
 checks[f.stem]={'receipt':copy_map[next(p for p,v in copy_map.items()if v['original']==f.relative_to(r).as_posix())],'exit_code':o.get('exit_code'),'elapsed_seconds':o.get('elapsed_seconds')}
o={'schema':'arcora-public-service-local-evidence-ledger/v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_main':base,'code_commit':code,'code_commit_files_sha256':code_map,'current_covered_source_files':371,'current_covered_source_map_sha256':'7fd564c8bf0ec2bd3434635a06ff046e9faec759996c78a2c6db47ed85b5619d','artifacts':artifacts,'copied_artifacts':copy_map,'final_checks':checks,'scope':{'local_software_verification':True,'running_services_attested':False,'operator_policy_approved':False,'candidate_submission_enabled':False,'fresh_proof_generated':False,'release_gate':'HOLD'},'publication_ci_observed':False,'note':'Artifact ledger excludes itself. Original relative receipt paths are retained, and copy_map binds portable destinations. Early failed-run receipts are historical; only final checks share full frozen source map. Documentation changes after code commit are metadata outside covered service inventory.'}
with (dst/'artifact-ledger.json').open('x')as f:f.write(json.dumps(o,indent=2)+'\n')
print({'artifacts':len(artifacts),'copied':len(copy_map),'bytes':sum(x['bytes']for x in artifacts.values()),'ledger_sha256':hashlib.sha256((dst/'artifact-ledger.json').read_bytes()).hexdigest()})
