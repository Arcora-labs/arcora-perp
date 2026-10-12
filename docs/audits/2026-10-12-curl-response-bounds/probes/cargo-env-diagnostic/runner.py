#!/opt/homebrew/bin/python3.12
import json,os,sys
from pathlib import Path
p=Path(__file__).parent/"child-environment.json"
with p.open("x") as f:json.dump({n:os.environ.get(n) for n in ["PATH","DYLD_FALLBACK_LIBRARY_PATH","DYLD_LIBRARY_PATH","LD_LIBRARY_PATH"]},f,indent=2)
os.execv(sys.argv[1],sys.argv[1:])
