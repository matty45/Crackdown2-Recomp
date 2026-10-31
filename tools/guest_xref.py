"""Static cross-reference helper for the recompiled Crackdown 2 image.

Needs a raw dump of guest memory at 0x82000000 (the loaded, TU-patched XEX image;
28 MB, not part of the repo) and the pdata.csv function table from
tools/dump_pdata.py. Point at them with the C2_IMAGE / C2_PDATA environment
variables or the defaults below.

  python3 tools/guest_xref.py 821157B8            # code that builds this address (lis/addi, lis/ori)
  python3 tools/guest_xref.py callers 825CE628    # bl call sites of a function
"""
import os, sys, struct, bisect, re
HERE=os.path.dirname(os.path.abspath(__file__))
IMG=os.environ.get("C2_IMAGE", os.path.join(HERE, "..", "..", "imgdump", "image_82000000.bin")); BASE=0x82000000
PDATA=os.environ.get("C2_PDATA", os.path.join(HERE, "..", "..", "imgdump", "pdata.csv"))
data=open(IMG,"rb").read()
n=len(data)//4
words=struct.unpack(">%dI"%n, data[:n*4])
# function table from pdata.csv (start,size) + names
funcs=[]
for line in open(PDATA):
    p=line.strip().split(",")
    if len(p)>=2 and re.match(r"^[0-9A-Fa-f]{8}$",p[0]):
        funcs.append((int(p[0],16),int(p[1])))
funcs.sort(); starts=[f[0] for f in funcs]
names={}
for line in list(open(os.path.join(HERE, "..", "default_names.toml")))+list(open(os.path.join(HERE, "..", "default_functions.toml"))):
    m=re.match(r'(0x[0-9A-Fa-f]+)\s*=\s*\{\s*name\s*=\s*"([^"]+)"', line)
    if m: names[int(m.group(1),16)]=m.group(2)
def func_of(addr):
    i=bisect.bisect_right(starts,addr)-1
    if i>=0 and starts[i]<=addr<starts[i]+funcs[i][1]:
        return starts[i], names.get(starts[i], "sub_%08X"%starts[i])
    return None,"?"
def xrefs(target):
    hi=target>>16; lo=target&0xFFFF
    lis_hi = hi + (1 if lo>=0x8000 else 0)
    out=[]
    for i,w in enumerate(words):
        op=w>>26
        if op==14 and (w&0xFFFF)==lo:      # addi rD, rA, lo
            ra=(w>>16)&31
            for j in range(max(0,i-12),i):
                v=words[j]
                if (v>>26)==15 and ((v>>21)&31)==ra and ((v>>16)&31)==0 and (v&0xFFFF)==(lis_hi&0xFFFF):
                    out.append(BASE+i*4); break
        elif op==24 and (w&0xFFFF)==lo:    # ori rA, rS, lo
            rs=(w>>21)&31
            for j in range(max(0,i-12),i):
                v=words[j]
                if (v>>26)==15 and ((v>>21)&31)==rs and (v&0xFFFF)==(hi&0xFFFF):
                    out.append(BASE+i*4); break
    return out
if __name__=="__main__" and sys.argv[1]!="callers":
    for arg in sys.argv[1:]:
        t=int(arg,16)
        for a in xrefs(t):
            fs,fn=func_of(a)
            print(f"{t:08X} <- {a:08X} in {fn} ({fs:08X})" if fs else f"{t:08X} <- {a:08X} in ?")

def callers(target):
    out=[]
    for i,w in enumerate(words):
        if (w>>26)==18 and (w&3)==1:   # bl
            li=w&0x03FFFFFC
            if li&0x02000000: li-=0x04000000
            if BASE+i*4+li==target: out.append(BASE+i*4)
    return out
if __name__=="__main__" and len(sys.argv)>2 and sys.argv[1]=="callers":
    for arg in sys.argv[2:]:
        t=int(arg,16)
        for a in callers(t):
            fs,fn=func_of(a); print(f"{t:08X} called from {a:08X} in {fn} ({fs:08X})" if fs else f"{t:08X} called from {a:08X}")
