from pathlib import Path
import datetime,hashlib,json,shutil,subprocess
r=Path.cwd();src=r/'target/candidate-transport-validation-20261012';dst=r/'docs/audits/2026-10-12-candidate-fixture-http'
for n in ['receipts','logs','tools']: (dst/n).mkdir(exist_ok=True)
selected=[]
for f in src.iterdir():
 if f.is_file() and (f.suffix in {'.json','.log'} or f.name in {'record_check.py','gateway_smoke.py','prepare_packet.py'}):selected.append(f)
for n in ['checks','pr55-main-refresh']:
 selected += [f for f in (src/n).iterdir() if f.is_file() and f.suffix in {'.json','.log','.py','.txt','.zip'}]
selected += []

assert any(f.name=='preservation-final.json' for f in selected)
copy_map={}
for f in sorted(set(selected)):
 rel=f.relative_to(src).as_posix();name=rel.replace('/','--')
 sub='logs' if f.suffix in {'.log','.zip'} else 'tools' if f.suffix=='.py' else 'receipts'
 target=dst/sub/name
 assert not target.exists(),target
 shutil.copyfile(f,target)
 copy_map[target.relative_to(dst).as_posix()]={'original':f.relative_to(r).as_posix(),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size}
code='a716f0c0fe6305749844d4f16cabbff19541b2d2';base='29be35c7a66c20563fb83812039eaaf1aa05d80a'
paths=subprocess.check_output(['git','diff','--name-only',base,code],text=True).splitlines()
code_map={p:hashlib.sha256(subprocess.check_output(['git','show',code+':'+p])).hexdigest()for p in paths}
artifacts={f.relative_to(dst).as_posix():{'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size}for f in dst.rglob('*') if f.is_file()}
checks={}
final_names={'gateway-final','workspace-clippy-final','workspace-format','new-python-published','pins-final'}
for f in (src/'checks').glob('*.json'):
 o=json.loads(f.read_text());
 if f.stem not in final_names:continue
 assert o.get('passed',o.get('exit_code')==0),f
 if 'source_inventory_unchanged'in o:assert o['source_inventory_unchanged']and o['source_files']==373 and o['source_map_sha256']=='69e339182071f166942be65ced7857f27f401093315ba48b0bea73f5551661e1'
 checks[f.stem]={'receipt':copy_map[next(p for p,v in copy_map.items()if v['original']==f.relative_to(r).as_posix())],'exit_code':o.get('exit_code'),'elapsed_seconds':o.get('elapsed_seconds')}
o={'schema':'arcora-candidate-fixture-http-local-evidence-ledger/v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_main':base,'code_commit':code,'code_commit_files_sha256':code_map,'current_covered_source_files':373,'current_covered_source_map_sha256':'69e339182071f166942be65ced7857f27f401093315ba48b0bea73f5551661e1','artifacts':artifacts,'copied_artifacts':copy_map,'final_checks':checks,'scope':{'local_software_verification':True,'running_services_attested':False,'operator_policy_approved':False,'candidate_submission_enabled':False,'fresh_proof_generated':False,'release_gate':'HOLD'},'publication_ci_observed':False,'note':'Artifact ledger excludes itself. Original relative receipt paths are retained, and copy_map binds portable destinations. Early failed-run receipts are historical; only final checks share full frozen source map. Documentation changes after code commit are metadata outside covered service inventory.'}
with (dst/'artifact-ledger.json').open('x')as f:f.write(json.dumps(o,indent=2)+'\n')
print({'artifacts':len(artifacts),'copied':len(copy_map),'bytes':sum(x['bytes']for x in artifacts.values()),'ledger_sha256':hashlib.sha256((dst/'artifact-ledger.json').read_bytes()).hexdigest()})
