import datetime,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path.cwd();OUT=ROOT/'target/handoff-validation-20261012'
b=json.loads((OUT/'baseline.json').read_text());amend=json.loads((OUT/'change-intent.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
changed=[p for p,h in b['frozen_sha256'].items() if not(ROOT/p).is_file() or sha(ROOT/p)!=h]
allowed=set(b['allowed_existing_paths']+amend['additional_allowed_existing_paths'])
unexpected=[p for p in changed if p not in allowed]
main=(ROOT/'crates/gateway/src/main.rs').read_text()
for m in ['candidate_handoff','candidate_handoff_lock_tests','candidate_handoff_tests']:
    main=main.replace('#[cfg(test)]\nmod '+m+';\n','')
old=subprocess.check_output(['git','show',b['base_main']+':crates/gateway/src/main.rs'],text=True)
oldci=subprocess.check_output(['git','show',b['base_main']+':.github/workflows/ci.yml'])
a11='.github/workflows/a11-release-evidence.yml';olda11=subprocess.check_output(['git','show',b['base_main']+':'+a11])
line=b'          python3 -m unittest discover -s scripts/local-verification -p test_release_manifest.py\n'
new=line+b'          python3 -m unittest discover -s scripts/local-verification -p test_candidate_identity_manifest.py\n'
assert olda11.count(line)==1
actuala11=(ROOT/a11).read_bytes()
a11_exact=actuala11==olda11 or actuala11==olda11.replace(line,new)
external=[]
for e in b['external']:
    p=Path(e['path']);status=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=p,text=True);head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip();staged=hashlib.sha256(subprocess.check_output(['git','diff','--cached','--binary'],cwd=p)).hexdigest();dirty=[f for f,h in e['dirty_file_sha256'].items() if not(p/f).is_file() or sha(p/f)!=h]
    external.append({'name':e['name'],'path':str(p),'head':head,'dirty_count':len(status.splitlines()),'same_head':head==e['head'],'same_status':status==e['status'],'same_staged_diff':staged==e['staged_binary_diff_sha256'],'dirty_files_changed':dirty,'passed':head==e['head'] and status==e['status'] and staged==e['staged_binary_diff_sha256'] and not dirty})
r={'schema':'arcora-handoff-preservation-v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_main':b['base_main'],'frozen_file_count':len(b['frozen_sha256']),'unchanged_frozen_file_count':len(b['frozen_sha256'])-len(changed),'intentional_changed_existing_files':changed,'unexpected_changed_existing_files':unexpected,'production_main_unchanged_after_removing_six_test_wire_lines':main==old,'ci_workspace_workflow_byte_exact':(ROOT/'.github/workflows/ci.yml').read_bytes()==oldci,'a11_exact_old_or_one_added_discovery_command':a11_exact,'external':external}
r['passed']=not unexpected and main==old and r['ci_workspace_workflow_byte_exact'] and a11_exact and all(e['passed'] for e in external)
path=OUT/(sys.argv[1]+'.json');assert not path.exists();path.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));assert r['passed']
