#!/usr/bin/env python3
"""Walk SWF tags; print ExportAssets/SymbolClass names, DoAction/DoInitAction AS2 constant pools, and DefineEditText var names."""
import struct, sys, pathlib
def rect_len(b):
    nbits = b[0] >> 3; return (5 + 4*nbits + 7)//8
def tags(d):
    pos = 0
    while pos+2 <= len(d):
        h = struct.unpack("<H", d[pos:pos+2])[0]; code, ln = h >> 6, h & 0x3f; pos += 2
        if ln == 0x3f: ln = struct.unpack("<I", d[pos:pos+4])[0]; pos += 4
        yield code, d[pos:pos+ln]; pos += ln
def as2_strings(body):
    out = []; p = 0
    while p < len(body):
        op = body[p]; p += 1
        if op == 0: continue
        ln = 0
        if op >= 0x80: ln = struct.unpack("<H", body[p:p+2])[0]; p += 2
        data = body[p:p+ln]; p += ln
        if op == 0x88:  # ConstantPool
            n = struct.unpack("<H", data[:2])[0]; out += [s.decode("utf8","replace") for s in data[2:].split(b"\0")[:n]]
        elif op == 0x96:  # Push
            q = 0
            while q < len(data):
                t = data[q]; q += 1
                if t == 0: e = data.find(b"\0", q); out.append(data[q:e].decode("utf8","replace")); q = e+1
                elif t in (1,): q += 4
                elif t == 2 or t == 3: pass
                elif t == 4 or t == 5: q += 1
                elif t == 6: q += 8
                elif t == 7: q += 4
                elif t == 8: q += 1
                elif t == 9: q += 2
    return out
NAMES = {56:"ExportAssets",76:"SymbolClass",12:"DoAction",59:"DoInitAction",37:"DefineEditText",7:"DefineButton",34:"DefineButton2",39:"DefineSprite",1000:"GFxExporterInfo",1001:"DefineExternalImage",1002:"FontTextureInfo",1004:"DefineExternalGradient",1005:"DefineGradientMap",1006:"DefineCompactedFont",1007:"DefineExternalSound",1008:"DefineExternalStreamSound",1009:"DefineSubImage",1010:"DefineExternalImage2"}
for f in sys.argv[1:]:
    d = pathlib.Path(f).read_bytes(); hl = 8 + rect_len(d[8:]) + 4
    body = d[hl:]
    print(f"=== {f}")
    def walk(body, depth=0):
        for code, data in tags(body):
            ind = "  "*depth
            if code in (56,76):
                n = struct.unpack("<H", data[:2])[0]; p = 2; items=[]
                for _ in range(n):
                    cid = struct.unpack("<H", data[p:p+2])[0]; e = data.find(b"\0", p+2); items.append(f"{cid}:{data[p+2:e].decode('utf8','replace')}"); p = e+1
                print(ind+f"{NAMES[code]}: {items}")
            elif code == 12 or code == 59:
                off = 2 if code == 59 else 0
                s = as2_strings(data[off:]); 
                if s: print(ind+f"{NAMES[code]}: {s}")
            elif code == 39:
                print(ind+f"Sprite id={struct.unpack('<H',data[:2])[0]}"); walk(data[4:], depth+1)
            elif code in (1000,1001,1009,1010):
                print(ind+f"{NAMES[code]}: {data[:80]}")
    walk(body)
