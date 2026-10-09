#!/usr/bin/env python3
import os, sys
compiler, *args = sys.argv[1:]
if "riscv64im-succinct-zkvm-elf" in args:
    args.append("--remap-path-prefix=/Users/huseyinarslan/Desktop/arcora-perp/repo=/Users/huseyinarslan/kimi-bridge/worktrees/Arcora-labs__arcora-perp/clock-anchor-20261009")
os.execv(compiler, [compiler, *args])
