#!/usr/bin/env python3
"""Extract an Xbox 360 game ISO (XDVDFS / GDFX) to a directory. Pure Python."""
import os, struct, sys

SECTOR = 0x800
MAGIC = b'MICROSOFT*XBOX*MEDIA'
# Known game-partition offsets for various disc layouts.
PARTITION_OFFSETS = [0x0, 0x2080000, 0xFD90000, 0x18300000, 0x1FB20000]

def find_partition(f):
    for po in PARTITION_OFFSETS:
        f.seek(po + 32 * SECTOR)
        hdr = f.read(SECTOR)
        if hdr[:20] == MAGIC:
            return po, hdr
    raise SystemExit("No XDVDFS volume descriptor found")

def read_dir(f, po, sector, size):
    f.seek(po + sector * SECTOR)
    return f.read(size)

def walk(f, po, dir_sector, dir_size, rel, out, stats):
    if dir_size == 0:
        return
    data = read_dir(f, po, dir_sector, dir_size)
    stack = [0]
    seen = set()
    while stack:
        off = stack.pop()
        if off in seen or off + 14 > len(data):
            continue
        seen.add(off)
        left, right, start, size, attr, nlen = struct.unpack_from('<HHIIBB', data, off)
        if left == 0xFFFF or (left == 0 and right == 0 and start == 0 and size == 0 and nlen == 0):
            # padding / empty
            if left == 0xFFFF:
                continue
        name = data[off + 14:off + 14 + nlen].decode('latin-1')
        if left:
            stack.append(left * 4)
        if right:
            stack.append(right * 4)
        if nlen == 0:
            continue
        path = os.path.join(rel, name)
        full = os.path.join(out, path)
        if attr & 0x10:
            os.makedirs(full, exist_ok=True)
            walk(f, po, start, size, path, out, stats)
        else:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'wb') as o:
                pos = f.tell()
                f.seek(po + start * SECTOR)
                remaining = size
                while remaining > 0:
                    chunk = f.read(min(remaining, 8 << 20))
                    if not chunk:
                        raise SystemExit(f"short read in {path}")
                    o.write(chunk)
                    remaining -= len(chunk)
            stats['files'] += 1
            stats['bytes'] += size
            if stats['files'] % 200 == 0:
                print(f"  ... {stats['files']} files, {stats['bytes'] / 2**20:.0f} MiB", flush=True)

def main():
    iso, out = sys.argv[1], sys.argv[2]
    with open(iso, 'rb') as f:
        po, hdr = find_partition(f)
        root_sector, root_size = struct.unpack_from('<II', hdr, 20)
        print(f"partition offset={po:#x} root_sector={root_sector} root_size={root_size}")
        stats = {'files': 0, 'bytes': 0}
        os.makedirs(out, exist_ok=True)
        walk(f, po, root_sector, root_size, '', out, stats)
        print(f"done: {stats['files']} files, {stats['bytes']} bytes")

if __name__ == '__main__':
    main()
