#!/usr/bin/env python3
"""Recover selectors in EVM runtime: PUSH4 literals, plus 4-byte-aligned constants
built as PUSHn v / PUSHm s / SHL (solc's constant optimizer drops trailing zero bits)
and left-aligned PUSH32 literals. Usage: <runtime.hex> name=sel ..."""
import sys
b=bytes.fromhex(open(sys.argv[1]).read().strip().removeprefix('0x'))
ins=[];i=0
while i<len(b):
    o=b[i]
    if 0x60<=o<=0x7f:
        n=o-0x5f; ins.append((i,o,int.from_bytes(b[i+1:i+1+n],'big'))); i+=n+1
    else:
        ins.append((i,o,None)); i+=1
push4=set();shl={};p32=set()
for k,(pc,o,v) in enumerate(ins):
    if o==0x63: push4.add(v)
    if o==0x7f and v and v&((1<<224)-1)==0: p32.add(v>>224)
    if k+2<len(ins) and v is not None and ins[k+1][2] is not None and ins[k+2][1]==0x1b:
        s=ins[k+1][2]
        if s<256 and v and s>=224 and s<=255:
            c=v<<s
            if c<(1<<256) and c&((1<<224)-1)==0: shl.setdefault(c>>224,[]).append((pc,hex(v),s))
print(f"runtime_bytes={len(b)} instructions={len(ins)} push4_distinct={len(push4)} shl_constants_distinct={len(shl)} push32_aligned={len(p32)}")
for a in sys.argv[2:]:
    n,x=a.split('=');x=int(x,16)
    print(f"{n} 0x{x:08x} raw_hex={b.hex().count(f'{x:08x}')} push4={int(x in push4)} shl={shl.get(x,[])} push32={int(x in p32)}")
print("all_shl_constants:",sorted(f"{k:08x}" for k in shl))
