#!/usr/bin/env python3
"""Identify Crackdown 2 DLC packages and check them against the known-good hashes from the README.

    python tools/verify_dlc.py <package> [...]

Each argument is a LIVE/PIRS container (or a folder, which is searched). Prints the content type, display name,
size and SHA-256 of each, and whether it matches a known package.
"""
import hashlib
import os
import struct
import sys

TITLE_ID = 0x4D5308BC
KNOWN = {
    "cf679bb4a061f9c7319eb1d5e4297888a1ab52b73436dc0b08c47f0528c774fd": "Toy Box Pack",
    "a1064677c4a756c4c82dc79cda60622f15a19e14393ae661e1ce4b9ccc6ad480": "Deluge Pack",
    "1ee257b70ec9b61bf8b7fac47579d9982a7bcdd1d47080260ecbd1f4cd09e372": "Pre-Order Armor",
}
CONTENT_TYPES = {0x00000002: "marketplace content", 0x00009000: "avatar item", 0x00000001: "saved game",
                 0x000B0000: "title update"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def describe(path):
    with open(path, "rb") as f:
        head = f.read(0x1000)
    magic = head[:4]
    if magic not in (b"LIVE", b"PIRS", b"CON "):
        return None
    ctype = struct.unpack_from(">I", head, 0x344)[0]
    title = struct.unpack_from(">I", head, 0x360)[0]
    name = head[0x411:0x411 + 0x100].decode("utf-16-be", "replace").split("\0")[0]
    return magic.decode(), ctype, title, name


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    files = []
    for a in sys.argv[1:]:
        if os.path.isdir(a):
            for d, _, fs in os.walk(a):
                files += [os.path.join(d, f) for f in sorted(fs)]
        else:
            files.append(a)
    bad = 0
    for p in files:
        d = describe(p)
        if not d:
            continue
        magic, ctype, title, name = d
        digest = sha256(p)
        kind = CONTENT_TYPES.get(ctype, f"type {ctype:08X}")
        known = KNOWN.get(digest)
        if title != TITLE_ID:
            verdict = f"not Crackdown 2 (title {title:08X})"
            bad += 1
        elif ctype != 0x00000002:
            verdict = f"{kind}: not game content, skip"
        elif known:
            verdict = f"OK, matches known-good {known}"
        else:
            verdict = "unknown hash: a different version or a corrupt download"
            bad += 1
        print(f"{magic} {kind:<20} {name!r:<28} {os.path.getsize(p):>11,}  {digest}\n   {os.path.basename(p)}: {verdict}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
