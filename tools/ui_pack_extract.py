#!/usr/bin/env python3
"""Extract Crackdown 2 UI .pack/.pack.toc archives. CFX entries -> also write .swf."""
import struct, sys, os, zlib, pathlib
def extract(pack, out):
    toc = pathlib.Path(str(pack) + ".toc").read_bytes()
    data = pathlib.Path(pack).read_bytes()
    assert toc[:4] == b"PACK", "bad toc"
    count = struct.unpack(">I", toc[12:16])[0]
    ents = [struct.unpack(">IIII", toc[0x20+i*16:0x30+i*16]) for i in range(count)]
    strtab = toc[0x20+count*16:]
    def name(off):
        s = strtab[off*2:]
        end = s.find(b"\x00\x00")
        # align to even boundary
        while end % 2: end = s.find(b"\x00\x00", end+1)
        return s[:end].decode("utf-16-be", "replace")
    os.makedirs(out, exist_ok=True)
    names = []
    for noff, doff, size, _ in ents:
        n = name(noff); blob = data[doff:doff+size]
        rel = n.replace("\\", "/"); p = pathlib.Path(out, rel); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
        tag = ""
        if blob[:3] == b"CFX":
            ulen = struct.unpack("<I", blob[4:8])[0]
            try:
                raw = zlib.decompress(blob[8:])
                swf = b"FWS" + blob[3:4] + struct.pack("<I", 8+len(raw)) + raw
                p.with_suffix(".swf").write_bytes(swf); tag = f" CFX->swf {len(raw)}B"
            except Exception as e: tag = f" CFX zlib fail {e}"
        elif blob[:3] == b"GFX": tag = " GFX(raw)"
        names.append(f"{n} off=0x{doff:x} size={size}{tag}")
    return names
if __name__ == "__main__":
    for pack in sys.argv[2:]:
        print(f"## {pack}")
        for l in extract(pack, os.path.join(sys.argv[1], pathlib.Path(pack).stem)): print("  " + l)
