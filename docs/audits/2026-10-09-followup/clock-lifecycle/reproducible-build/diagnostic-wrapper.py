#!/usr/bin/env python3
import json,os,sys
compiler,*args=sys.argv[1:]
identities={"perp_core":"85153213d10819ef","perp_core_guest":"2c8a895641ad00f3"}
if "--crate-name" in args and "riscv64im-succinct-zkvm-elf" in args:
 name=args[args.index("--crate-name")+1]
 if name in identities:
  before=args.copy()
  indices=[i for i,a in enumerate(args) if a.startswith("metadata=") and i>0 and args[i-1]=="-C"]
  assert len(indices)==1,"exactly one existing compiler crate identity required"
  args[indices[0]]="metadata="+identities[name]
  args.append("--remap-path-prefix=/Users/huseyinarslan/Desktop/arcora-perp/repo=/Users/huseyinarslan/kimi-bridge/worktrees/Arcora-labs__arcora-perp/clock-anchor-20261009")
  with open("/tmp/arcora-normalized-identities-20261010.jsonl","a") as f:
   f.write(json.dumps({"crate":name,"original_args":before,"normalized_args":args})+"\n")
os.execv(compiler,[compiler,*args])
