#!/usr/bin/env python3
import json,os,sys
compiler,*args=sys.argv[1:]
if "--crate-name" in args:
 name=args[args.index("--crate-name")+1]
 if name in ("perp_core","perp_core_guest"):
  with open("/tmp/arcora-original-identities-20261010.jsonl","a") as f:f.write(json.dumps({"crate":name,"args":args})+"\n")
  if name == "perp_core_guest": sys.exit(86)
os.execv(compiler,[compiler,*args])
