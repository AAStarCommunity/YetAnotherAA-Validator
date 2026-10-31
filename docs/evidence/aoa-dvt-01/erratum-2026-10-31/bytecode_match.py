#!/usr/bin/env python3
"""Compare a forge artifact's deployedBytecode with on-chain runtime, masking only the
artifact's immutableReferences. Usage: <artifact.json> <runtime.hex>"""
import json,sys
d=json.load(open(sys.argv[1]))['deployedBytecode']
loc=bytearray(bytes.fromhex(d['object'].removeprefix('0x')));ch=bytearray(bytes.fromhex(open(sys.argv[2]).read().strip().removeprefix('0x')))
print(f"local_bytes={len(loc)} chain_bytes={len(ch)}")
if len(loc)!=len(ch): print("MATCH_MODULO_IMMUTABLES=False (length differs)"); sys.exit()
vals={}
for k,rs in (d.get('immutableReferences') or {}).items():
    for r in rs:
        s,l=r['start'],r['length']; vals.setdefault(k,set()).add(bytes(ch[s:s+l]).hex())
        ch[s:s+l]=bytes(l); loc[s:s+l]=bytes(l)
print("immutables_on_chain=",{k:sorted(v) for k,v in vals.items()})
diff=[i for i in range(len(loc)) if loc[i]!=ch[i]]
print(f"differing_bytes_outside_immutables={len(diff)} first={diff[:8]}")
print(f"MATCH_MODULO_IMMUTABLES={not diff}")
