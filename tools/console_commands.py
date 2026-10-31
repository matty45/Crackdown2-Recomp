"""Recover Crackdown 2's developer console command table statically.

Walks every call to RegisterCommand (sub_825D0E00: table, name, callback, 0,
help, category) and emulates the lis/addi/mr register setup to read the string
arguments. Writes console_cmds_full.txt next to the script; docs/console_commands.md
is generated from it. Needs the same image dump as guest_xref.py.
"""
import sys, struct
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guest_xref as xref
from guest_xref import words, BASE, data, func_of, callers
REG=0x825D0E00
def rd_utf16(addr):
    o=addr-BASE
    if o<0 or o>=len(data): return "?"
    out=[]
    while o+1<len(data):
        c=(data[o]<<8)|data[o+1]
        if c==0: break
        out.append(chr(c) if c<0xD800 else "?"); o+=2
        if len(out)>200: break
    return "".join(out)
def emulate(start, end):
    regs={}
    for i in range((start-BASE)//4, (end-BASE)//4):
        w=words[i]; op=w>>26; rd=(w>>21)&31; ra=(w>>16)&31; imm=w&0xFFFF; simm=imm-0x10000 if imm&0x8000 else imm
        if op==15:   # addis / lis
            regs[rd]=((regs.get(ra,0) if ra else 0)+(simm<<16))&0xFFFFFFFF
        elif op==14: # addi / li
            regs[rd]=((regs.get(ra,0) if ra else 0)+simm)&0xFFFFFFFF
        elif op==24: # ori
            regs[ra]=(regs.get(rd,0)|imm)&0xFFFFFFFF
        elif op==31 and ((w>>1)&0x3FF)==444: # or rA,rS,rB (mr)
            rb=(w>>11)&31; rs=rd
            if rs==rb: regs[ra]=regs.get(rs,0)
        elif op==18 and (w&3)==1:  # bl: assume r3..r10 clobbered? keep (they get reset before each call); drop r3 only
            regs.pop(3,None)
    return regs
rows=[]
for site in callers(REG):
    fs,fn=func_of(site)
    regs=emulate(fs if fs else site-120, site)
    name=rd_utf16(regs.get(4,0)); cb=regs.get(5,0); help_=rd_utf16(regs.get(7,0)); cat=rd_utf16(regs.get(8,0))
    rows.append((cat,name,cb,help_,fn,site))
rows.sort()
with open("console_cmds_full.txt","w") as f:
    for cat,name,cb,help_,fn,site in rows:
        f.write(f"{cat:28s} | {name:32s} | cb={cb:08X} | {help_[:110]:110s} | reg in {fn}\n")
print(len(rows),"registrations")
import collections
print(collections.Counter(r[0] for r in rows).most_common(40))
