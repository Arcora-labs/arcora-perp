from pathlib import Path
import datetime,hashlib,json,shutil,subprocess
r=Path.cwd();o=r/'target/candidate-transport-validation-20261012';p=r/'docs/audits/2026-10-12-candidate-fixture-http-compatibility';p.mkdir(exist_ok=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
copy={}
def put(src,rel):
 f=o/src;d=p/rel;d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,d);assert sha(f)==sha(d);copy[rel]={'original':str(f.relative_to(r)),'sha256':sha(f),'bytes':f.stat().st_size}
for n in ['fixture-compatibility','workspace-clippy-compatibility','workspace-format-compatibility','new-python-compatibility']:
 put('checks/'+n+'.json','receipts/'+n+'.json')
 for x in ['stdout','stderr']:put('checks/'+n+'.'+x+'.log','logs/'+n+'.'+x+'.log')
put('checks/pins-compatibility.json','receipts/pins-compatibility.json')
put('publication/compatibility-source-qa.json','receipts/compatibility-source-qa.json')
put('publication/vercel-initial-public-diagnosis.json','receipts/vercel-initial-public-diagnosis.json')
for n in ['rust-lint.log','a11-release.log']:
 put('publication/ci56-initial-8181880/'+n,'logs/initial-'+n)
for n in ['a11-release-capture.json','initial-ci-failure-diagnosis.json','snapshot-20261012T120416427591Z.json']:
 put('publication/ci56-initial-8181880/'+n,'receipts/initial-'+n)
put('record_check.py','tools/record_check.py')
put('prepare_compatibility_packet.py','tools/prepare_compatibility_packet.py')
if (o/'preservation-compatibility-final.json').exists():put('preservation-compatibility-final.json','receipts/preservation-compatibility-final.json')
code='90ab7e2acb0c173fb0e76a311ac9377e4363636f'
files=['crates/gateway/src/candidate_fixture_transport.rs','crates/gateway/src/candidate_fixture_transport_tests.rs','crates/gateway/src/main.rs','.github/workflows/a11-release-evidence.yml','docs/CANDIDATE_FIXTURE_HTTP.md','docs/ACTIVE_WORK.md']
blobs={n:hashlib.sha256(subprocess.check_output(['git','show',code+':'+n])).hexdigest()for n in files}
ledger={'schema':'arcora-candidate-fixture-http-compatibility-evidence/v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'initial_publication_head':'8181880a41dcd1bf1f1117270c0d0067e4c7b15f','compatibility_code_commit':code,'compatibility_code_blobs_sha256':blobs,'covered_source_files':373,'covered_source_map_sha256':'644a6c7c5f18a3557d619abacd2cb8a5acfed726f25ad5c7b23a5aff87c29db0','original_packet_ledger_sha256':sha(r/'docs/audits/2026-10-12-candidate-fixture-http/artifact-ledger.json'),'artifacts':{str(f.relative_to(p)):{'sha256':sha(f),'bytes':f.stat().st_size}for f in sorted(p.rglob('*'))if f.is_file()and f.name!='artifact-ledger.json'},'copied_artifacts':copy,'scope':{'local_focused_http_passed':18,'local_focused_failed':0,'local_focused_ignored':0,'local_python_passed':25,'local_clippy_and_format_passed':True,'current_full_gateway_local_run':False,'original_full697_source_is_historical':True,'publication_ci_observed':False,'candidate_submission_enabled':False,'fresh_proof_generated':False,'production_release':'HOLD'}}
(p/'artifact-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n');print({'artifacts':len(ledger['artifacts']),'ledger_sha256':sha(p/'artifact-ledger.json')})
