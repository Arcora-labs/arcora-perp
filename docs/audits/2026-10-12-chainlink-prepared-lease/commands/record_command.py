import datetime,hashlib,json,os,subprocess,sys,time
from pathlib import Path
OUT=Path(__file__).resolve().parent
name, payload_path=sys.argv[1:]
assert name.replace('-','').replace('_','').isalnum()
payload=json.loads(Path(payload_path).read_text())
paths=[Path(p).resolve() for p in payload.get('source_paths',[])]
def hashes():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
log=OUT/(name+'.log');stdout=OUT/(name+'.stdout.log');stderr=OUT/(name+'.stderr.log')
assert not any(p.exists() for p in [log,stdout,stderr,OUT/(name+'.json')]),'fresh receipt names required'
start=time.monotonic();before=hashes();observed=datetime.datetime.now(datetime.timezone.utc).isoformat()
env=os.environ.copy();env.update(payload.get('env',{}))
with stdout.open('wb') as so,stderr.open('wb') as se:
    code=subprocess.run(payload['argv'],cwd=payload.get('cwd'),env=env,stdout=so,stderr=se).returncode
log.write_bytes(stdout.read_bytes()+stderr.read_bytes())
after=hashes();data=log.read_bytes();lines=data.decode(errors='replace').splitlines()
receipt={'schema':'arcora-prepared-lease-command-v1','observed_start_utc':observed,'observed_end_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'name':name,'argv':payload['argv'],'cwd':payload.get('cwd'),'environment':payload.get('env',{}),'exit_code':code,'elapsed_seconds':round(time.monotonic()-start,3),'source_sha256_before':before,'source_sha256_after':after,'source_bytes_unchanged':before==after,'log':str(log),'log_sha256':hashlib.sha256(data).hexdigest(),'stdout_log':str(stdout),'stderr_log':str(stderr),'summaries':[s for s in lines if 'test result:' in s or 'tests passed' in s or 'Ran 47 tests' in s]}
(OUT/(name+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['name','exit_code','elapsed_seconds','source_bytes_unchanged','summaries']}),flush=True)
if code or before!=after:
    print('\n'.join(lines[-80:]),flush=True)
    sys.exit(code or 1)
