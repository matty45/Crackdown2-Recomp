#!/usr/bin/env python3
"""Minimal STFS (LIVE/PIRS/CON) container extractor for Xbox 360 title updates."""
import os, struct, sys, hashlib

HASH_SPACING = 170

def u24le(b): return b[0] | (b[1] << 8) | (b[2] << 16)
def u24be(b): return (b[0] << 16) | (b[1] << 8) | b[2]

class STFS:
    def __init__(self, data):
        self.d = data
        magic = data[0:4]
        assert magic in (b'LIVE', b'PIRS', b'CON '), magic
        self.header_size = struct.unpack('>I', data[0x340:0x344])[0]
        vd = data[0x379:0x379 + 0x24]
        self.block_separation = vd[2]
        self.ft_block_count = struct.unpack('<H', vd[3:5])[0]
        self.ft_block_number = u24le(vd[5:8])
        self.total_alloc = struct.unpack('>I', vd[0x1C:0x20])[0]
        self.title_id = struct.unpack('>I', data[0x360:0x364])[0]
        self.version = struct.unpack('>I', data[0x358:0x35C])[0]
        self.base_version = struct.unpack('>I', data[0x35C:0x360])[0]
        name = data[0x411:0x411 + 0x80].decode('utf-16-be', 'ignore').split('\0')[0]
        self.display_name = name
        # Verified empirically on a LIVE title update: block_separation bit0 set => single hash block.
        self.block_shift = 0 if (self.block_separation & 1) else 1
        self.data_start = (self.header_size + 0xFFF) & ~0xFFF

    def data_block_number(self, block_index):
        """Physical block of a data block, accounting for interleaved hash tables."""
        sh = self.block_shift
        num = ((block_index + 0xAA) // 0xAA) << sh
        if block_index >= 0xAA:
            num += ((block_index + 0x70E4) // 0x70E4) << sh
        if block_index >= 0x70E4:
            num += ((block_index + 0x4AF768) // 0x4AF768) << sh
        return num + block_index

    def block_to_offset(self, block_index):
        return self.data_start + (self.data_block_number(block_index) << 12)

    def hash_block_offset(self, block_index, level=0):
        # The level-0 table for a group of 170 data blocks sits right before the group.
        assert level == 0
        group_first = (block_index // HASH_SPACING) * HASH_SPACING
        phys = self.data_block_number(group_first) - (1 << self.block_shift)
        off = self.data_start + (phys << 12)
        if self.block_shift == 1 and (self.block_separation & 2):
            off += 0x1000  # second (active) copy of the table
        return off

    def next_block(self, block_index):
        off = self.hash_block_offset(block_index, 0)
        entry = off + (block_index % HASH_SPACING) * 0x18
        return u24be(self.d[entry + 0x15:entry + 0x18])

    def read_block(self, block_index):
        off = self.block_to_offset(block_index)
        return self.d[off:off + 0x1000]

    def entries(self):
        out = []
        blk = self.ft_block_number
        for _ in range(self.ft_block_count):
            tbl = self.read_block(blk)
            for i in range(0x1000 // 0x40):
                e = tbl[i * 0x40:(i + 1) * 0x40]
                if e[0] == 0:
                    continue
                flags = e[0x28]
                namelen = flags & 0x3F
                name = e[:namelen].decode('latin-1')
                is_dir = bool(flags & 0x80)
                contiguous = bool(flags & 0x40)
                nblocks = u24le(e[0x29:0x2C])
                start = u24le(e[0x2F:0x32])
                parent = struct.unpack('>H', e[0x32:0x34])[0]
                size = struct.unpack('>I', e[0x34:0x38])[0]
                out.append(dict(name=name, dir=is_dir, contiguous=contiguous,
                                blocks=nblocks, start=start, parent=parent, size=size))
            blk += 1  # file table blocks are contiguous in practice
        return out

    def read_file(self, ent):
        data = bytearray()
        blk = ent['start']
        remaining = ent['size']
        for n in range(ent['blocks']):
            chunk = self.read_block(blk)
            take = min(0x1000, remaining)
            data += chunk[:take]
            remaining -= take
            if remaining <= 0:
                break
            if ent['contiguous']:
                blk += 1
            else:
                blk = self.next_block(blk)
        return bytes(data)

def main():
    src, outdir = sys.argv[1], sys.argv[2]
    with open(src, 'rb') as f:
        s = STFS(f.read())
    print(f"magic ok; title_id={s.title_id:08X} version={s.version:#x} base={s.base_version:#x} "
          f"name='{s.display_name}' header_size={s.header_size:#x} shift={s.block_shift} "
          f"ft_blocks={s.ft_block_count}@{s.ft_block_number} alloc={s.total_alloc}")
    ents = s.entries()
    paths = {}
    for idx, e in enumerate(ents):
        parent = paths.get(e['parent'], '') if e['parent'] != 0xFFFF else ''
        p = os.path.join(parent, e['name']) if parent else e['name']
        paths[idx] = p
        full = os.path.join(outdir, p)
        if e['dir']:
            os.makedirs(full, exist_ok=True)
            print(f"[dir ] {p}")
        else:
            os.makedirs(os.path.dirname(full) or outdir, exist_ok=True)
            b = s.read_file(e)
            with open(full, 'wb') as f:
                f.write(b)
            print(f"[file] {p} size={e['size']} blocks={e['blocks']} start={e['start']} "
                  f"contig={e['contiguous']} sha256={hashlib.sha256(b).hexdigest()}")

if __name__ == '__main__':
    main()
