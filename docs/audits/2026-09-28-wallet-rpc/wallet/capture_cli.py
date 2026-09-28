import subprocess,sys,pathlib,json,time
root=pathlib.Path('/Users/huseyinarslan/.codex/worktrees/arcora-local-verification/dark-perp')
label,codepath=sys.argv[1:]
code=pathlib.Path(codepath).read_text()
cmd=['/Users/huseyinarslan/.codex/skills/playwright/scripts/playwright_cli.sh','-s=arcora-wallet2','run-code',code]
r=subprocess.run(cmd,capture_output=True,text=True,cwd=root)
out=root/'docs/audits/2026-09-28-wallet-rpc/wallet'
(out/(label+'.log')).write_text(r.stdout+r.stderr)
(out/(label+'.json')).write_text(json.dumps({'exit_code':r.returncode,'time':time.time(),'code_file':label+'.js'},indent=2)+'\n')
(out/(label+'.js')).write_text(code)
print(r.stdout[-3500:]); print(r.stderr[-500:]);sys.exit(r.returncode)
