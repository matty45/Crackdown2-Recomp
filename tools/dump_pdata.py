import struct, sys
data = open(sys.argv[1], 'rb').read()
base = 0x82000000
assert data[:2] == b'MZ'
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff = e_lfanew + 4
num_sections, opt_size = struct.unpack_from('<H', data, coff+2)[0], struct.unpack_from('<H', data, coff+16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
assert magic == 0x10b, hex(magic)
image_base = struct.unpack_from('<I', data, opt+28)[0]
num_dirs = struct.unpack_from('<I', data, opt+92)[0]
dirs = opt + 96
exc_rva, exc_size = struct.unpack_from('<II', data, dirs + 3*8)
print(f'image_base={image_base:#x} sections={num_sections} exception dir rva={exc_rva:#x} size={exc_size:#x} entries={exc_size//8}', file=sys.stderr)
out = open(sys.argv[2], 'w')
n = 0
for i in range(exc_size // 8):
    begin, d = struct.unpack_from('>II', data, exc_rva + i*8)
    prolog = d & 0xFF
    flen = (d >> 8) & 0x3FFFFF
    thirty_two = (d >> 30) & 1
    exc = (d >> 31) & 1
    out.write(f'{begin:08X},{flen*4},{prolog},{exc}\n')
    n += 1
print(f'wrote {n} entries', file=sys.stderr)
