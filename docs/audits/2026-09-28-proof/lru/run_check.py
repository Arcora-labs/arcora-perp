import hashlib,json,os,subprocess,sys,time
from pathlib import Path
root=Path('/Users/huseyinarslan/.codex/worktrees/arcora-local-verification/dark-perp')
evidence=Path('/tmp/arcora-lru-20260928')
name=sys.argv[1]
argv=sys.argv[2:]
paths=[*sorted((root/'vendor/sp1-prover').rglob('*')),root/'crates/sp1-host/Cargo.toml',root/'crates/sp1-host/Cargo.lock',root/'crates/prover-service/Cargo.toml',root/'crates/prover-service/Cargo.lock']
def hashes():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
before=hashes()
env=os.environ.copy()
env.update({'SP1_SKIP_PROGRAM_BUILD':'true','PROTOC':'/tmp/arcora-tools/protoc-29.3/bin/protoc','CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(root/'crates/sp1-host/target')})
env['PATH']='/tmp/arcora-tools/sp1-6.1.0:'+env['PATH']
start=time.time()
with (evidence/(name+'.log')).open('wb') as out:result=subprocess.run(argv,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT)
record={'argv':argv,'cwd':str(root),'environment':{k:env[k] for k in ['SP1_SKIP_PROGRAM_BUILD','PROTOC','CARGO_TARGET_DIR','CARGO_BUILD_JOBS']},'exit_code':result.returncode,'duration_seconds':round(time.time()-start,3),'owned_source_before':before,'owned_source_after':hashes(),'log_sha256':hashlib.sha256((evidence/(name+'.log')).read_bytes()).hexdigest()}
record['owned_source_unchanged']=record['owned_source_before']==record['owned_source_after']
(evidence/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k not in ['owned_source_before','owned_source_after']},indent=2))
print('\n'.join((evidence/(name+'.log')).read_text(errors='replace').splitlines()[-25:]))
raise SystemExit(result.returncode)
