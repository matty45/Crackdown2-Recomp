#!/usr/bin/env python3
"""Parse Crackdown 2 GameStrings.str: '2BSL' header, big-endian (hash,u32) index, UTF-16BE blob."""
import struct, sys
def load(path):
    d=open(path,"rb").read()
    assert d[:4]==b"2BSL"
    # find index start: first 8-byte-aligned run of (hash,off) where off strictly increases
    best=None
    for start in range(8,64,4):
        ents=[]; p=start; last=-1
        while p+8<=len(d):
            h,o=struct.unpack(">II",d[p:p+8])
            if o<=last or o>len(d)*2: break
            ents.append((h,o)); last=o; p+=8
        if best is None or len(ents)>len(best[1]): best=(start,ents,p)
    start,ents,blob=best
    return d,ents,blob
def resolve(d,ents,blob,h,mode):
    for hh,o in ents:
        if hh==h:
            off=blob+(o*2 if mode=="chars" else o)
            s=d[off:]; e=s.find(b"\x00\x00")
            while e%2: e=s.find(b"\x00\x00",e+1)
            return s[:e].decode("utf-16-be","replace")
    return None
if __name__=="__main__":
    d,ents,blob=load(sys.argv[1]); print(f"index entries={len(ents)} blob@0x{blob:x}", file=sys.stderr)
    hs=[int(x,16) for x in sys.argv[2:]]
    for mode in ("chars","bytes"):
        print(f"--- mode={mode}")
        for h in hs: print(f"{h:08X} -> {resolve(d,ents,blob,h,mode)!r}"[:120])
