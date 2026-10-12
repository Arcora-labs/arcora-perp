from pathlib import Path
import datetime,hashlib,json,shutil,subprocess
r=Path.cwd();o=r/'target/candidate-seal-validation-20261012';p=r/'docs/audits/2026-10-12-candidate-fixture-sealed';p.mkdir(exist_ok=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
copy={}
def put(src,rel):
 f=o/src;d=p/rel;d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,d);assert sha(f)==sha(d);copy[rel]={'original':str(f.relative_to(r)),'sha256':sha(f),'bytes':f.stat().st_size}
for f in sorted(o.glob('*.json')):put(f.name,'receipts/'+f.name)
for f in sorted((o/'checks').glob('*')):
 if f.is_file():put(str(f.relative_to(o)),('logs/'if f.name.endswith('.log')else'receipts/')+f.name)
for f in sorted((o/'pr56-main-refresh').glob('*')):
 if f.is_file():put(str(f.relative_to(o)),('logs/'if f.name.endswith(('.log','.zip'))else'receipts/')+'pr56-main-refresh--'+f.name)
for f in ['record_check.py','prepare_packet.py']:put(f,'tools/'+f)
code='52600351c4a3e5a9ad0c565175dc3c9561f30dfd';paths=['.github/workflows/a11-release-evidence.yml','crates/gateway/src/main.rs','crates/gateway/src/candidate_fixture_transport.rs','crates/gateway/src/candidate_fixture_seal.rs','crates/gateway/src/candidate_fixture_seal_tests.rs','docs/CANDIDATE_FIXTURE_SEALED_CHANNEL.md']
blobs={n:hashlib.sha256(subprocess.check_output(['git','show',code+':'+n])).hexdigest()for n in paths}
ledger={'schema':'arcora-candidate-signed-sealed-fixture-local-evidence/v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_main':'60eceef733613fe6d491548d35eb4fdb7c0809bd','code_commit':code,'code_commit_files_sha256':blobs,'covered_source_files':375,'covered_source_map_sha256':'ec07ccd9cba6f2b52b7600e149715805bd7d58e84195c4a947e4c75102cf9b89','artifacts':{str(f.relative_to(p)):{'sha256':sha(f),'bytes':f.stat().st_size}for f in sorted(p.rglob('*'))if f.is_file()and f.name!='artifact-ledger.json'},'copied_artifacts':copy,'local_validation':{'new_sealed_passed':19,'new_sealed_failed':0,'new_sealed_ignored':0,'full_gateway_passed':716,'full_gateway_failed':0,'full_gateway_ignored':23,'python_passed':25,'format_passed':True,'clippy_warnings_denied_passed':True,'pins_reviewed':21,'pins_candidate':9,'pins_auxiliary':2},'scope':{'configured_ECDSA_key_possession':True,'sender_static_X25519_possession_proved':False,'running_services_attested':False,'operator_policy_approved':False,'candidate_submission_enabled':False,'fresh_proof_generated':False,'publication_ci_observed':False,'production_release':'HOLD'},'note':'Ledger excludes itself. Portable files bind their captured original paths; local 375-source results and prior-base main CI do not substitute for future exact publication-head CI.'}
(p/'artifact-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n');print({'artifact_count':len(ledger['artifacts']),'ledger_sha256':sha(p/'artifact-ledger.json')})
