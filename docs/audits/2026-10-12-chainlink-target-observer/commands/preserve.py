import datetime,hashlib,json,subprocess,sys
from pathlib import Path
root=Path.cwd();out=root/'target/candidate-target-validation-20261012'
b=json.loads((out/'baseline.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
changed=[p for p,h in b['frozen_sha256'].items() if not(root/p).is_file() or sha(root/p)!=h]
unexpected=[p for p in changed if p not in b['allowed_existing_paths']]
a11='.github/workflows/a11-release-evidence.yml'
old=subprocess.check_output(['git','show',b['base_main']+':'+a11])
unit=b'          python3 -m unittest discover -s scripts/local-verification -p test_candidate_identity_manifest.py\n'
addition=b'          python3 -m unittest discover -s scripts/local-verification -p test_candidate_target_observer.py\n'
stack=b'          ARCORA_RUN_MANIFEST_ANVIL=1 ARCORA_MANIFEST_ANVIL_EVIDENCE=/tmp/arcora-local-drills/manifest-anvil.json python3 -m unittest discover -s scripts/local-verification -p test_release_manifest.py -v\n'
step=b'      - name: Candidate target identity against owned seven-contract Anvil stack\n        run: |\n          ARCORA_RUN_CANDIDATE_TARGET_ANVIL=1 ARCORA_CANDIDATE_TARGET_ANVIL_EVIDENCE=/tmp/arcora-local-drills/candidate-target-anvil.json python3 -m unittest discover -s scripts/local-verification -p test_candidate_target_anvil.py -v\n'
assert old.count(unit)==old.count(stack)==1
expected=old.replace(unit,unit+addition).replace(stack,stack+step)
external=[]
for e in b['external']:
 p=Path(e['path']);status=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=p,text=True);head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip();staged=hashlib.sha256(subprocess.check_output(['git','diff','--cached','--binary'],cwd=p)).hexdigest()
 altered=[f for f,h in e['dirty_file_sha256'].items() if not(p/f).is_file() or sha(p/f)!=h]
 external.append({'name':e['name'],'path':str(p),'head':head,'dirty_count':len(status.splitlines()),'same_head':head==e['head'],'same_status':status==e['status'],'same_staged_diff':staged==e['staged_binary_diff_sha256'],'dirty_files_changed':altered,'passed':head==e['head'] and status==e['status'] and staged==e['staged_binary_diff_sha256'] and not altered})
r={'schema':'arcora-candidate-target-preservation-v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_main':b['base_main'],'frozen_files':len(b['frozen_sha256']),'unchanged_frozen_files':len(b['frozen_sha256'])-len(changed),'planned_existing_changes':changed,'unexpected_changes':unexpected,'a11_exact_two_new_gates_only':(root/a11).read_bytes()==expected,'ci_workspace_workflow_byte_exact':sha(root/'.github/workflows/ci.yml')==b['frozen_sha256']['.github/workflows/ci.yml'],'external':external}
r['passed']=not unexpected and r['a11_exact_two_new_gates_only'] and r['ci_workspace_workflow_byte_exact'] and all(e['passed'] for e in external)
p=out/(sys.argv[1]+'.json');assert not p.exists();p.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));assert r['passed']
