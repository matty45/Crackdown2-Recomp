#!/usr/bin/env python3
"""Install Crackdown 2 DLC packages (Xbox 360 LIVE/PIRS containers) for the recomp.

rexglue does not read STFS packages at run time. Marketplace content has to be
extracted into the runtime's user data root as

    <user_data_root>/0000000000000000/4D5308BC/00000002/<package file name>/...

plus a .header file carrying the package metadata and the licence mask:

    <user_data_root>/0000000000000000/4D5308BC/Headers/00000002/<package file name>.header

This script does both for every package you pass it:

    python3 tools/dlc_install.py <package> [<package> ...] [--user-data-root DIR] [--license 0xFFFFFFFF]

Default user data root: Documents\\crackdown2 on Windows, ~/.local/share/crackdown2
elsewhere (the SDK's GetUserFolder()/<app name>). Pass --user-data-root if you
launch with --user_data_root=... . The game checks licences per package through
XamContentCreate (reads the .header) and globally through XamContentGetLicenseMask
(the --license_mask cvar); its developer console also has "togglelicenseoverride"
(the DLC LICENSE row of the hidden cheat menu).

Crackdown 2 marketplace content (title 4D5308BC): Toy Box Pack (free preview and
premium), Deluge Pack, plus avatar items and themes.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stfs_extract import STFS  # noqa: E402

TITLE_ID = 0x4D5308BC
CONTENT_MARKETPLACE = 0x00000002
XCONTENT_AGGREGATE_SIZE = 0x148


def default_user_root():
    """Mirror rex::filesystem::GetUserFolder() / "crackdown2": the Documents folder on Windows (via the shell,
    so a redirected Documents folder is honoured), $XDG_DATA_HOME or ~/.local/share elsewhere."""
    if sys.platform.startswith("win"):
        import ctypes
        import ctypes.wintypes
        buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        csidl_personal = 5  # FOLDERID_Documents
        if ctypes.windll.shell32.SHGetFolderPathW(None, csidl_personal, None, 0, buf) == 0 and buf.value:
            base = buf.value
        else:
            base = os.path.join(os.path.expanduser("~"), "Documents")
        return os.path.join(base, "crackdown2")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "crackdown2")


def build_header(display_name, file_name, content_type, title_id, license_mask):
    """XCONTENT_AGGREGATE_DATA (big-endian fields) followed by the host-order licence mask."""
    h = bytearray(XCONTENT_AGGREGATE_SIZE)
    struct.pack_into(">I", h, 0, 1)                      # device_id
    struct.pack_into(">I", h, 4, content_type)
    name = display_name.encode("utf-16-be")[: 127 * 2]
    h[8:8 + len(name)] = name                             # display_name wchar[128], NUL padded
    fn = file_name.encode("ascii", "ignore")[:42]
    h[0x108:0x108 + len(fn)] = fn                         # file_name char[42]
    struct.pack_into(">Q", h, 0x138, 0)                   # xuid
    struct.pack_into(">I", h, 0x140, title_id)
    return bytes(h) + struct.pack("<I", license_mask)     # the runtime freads this into a host uint32


def extract_all(pkg, outdir):
    paths = {}
    count = 0
    for idx, e in enumerate(pkg.entries()):
        parent = paths.get(e["parent"], "") if e["parent"] != 0xFFFF else ""
        p = os.path.join(parent, e["name"]) if parent else e["name"]
        paths[idx] = p
        full = os.path.join(outdir, p)
        if e["dir"]:
            os.makedirs(full, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(full) or outdir, exist_ok=True)
        with open(full, "wb") as f:
            f.write(pkg.read_file(e))
        count += 1
    return count


def install(package_path, user_root, license_mask):
    data = open(package_path, "rb").read()
    pkg = STFS(data)
    if pkg.title_id != TITLE_ID:
        print(f"  warning: {os.path.basename(package_path)} is for title {pkg.title_id:08X}, not Crackdown 2")
    content_type = struct.unpack(">I", data[0x344:0x348])[0]
    if content_type != CONTENT_MARKETPLACE:
        print(f"  note: content type is {content_type:08X} (not marketplace 00000002); installing under that type")
    file_name = os.path.basename(package_path)
    pkg_dir = os.path.join(user_root, "0000000000000000", f"{pkg.title_id:08X}", f"{content_type:08X}", file_name)
    hdr_dir = os.path.join(user_root, "0000000000000000", f"{pkg.title_id:08X}", "Headers", f"{content_type:08X}")
    os.makedirs(pkg_dir, exist_ok=True)
    os.makedirs(hdr_dir, exist_ok=True)
    count = extract_all(pkg, pkg_dir)
    with open(os.path.join(hdr_dir, file_name + ".header"), "wb") as f:
        f.write(build_header(pkg.display_name, file_name, content_type, pkg.title_id, license_mask))
    print(f"  '{pkg.display_name}': {count} files -> {pkg_dir}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("packages", nargs="+", help="LIVE/PIRS package files")
    ap.add_argument("--user-data-root", default=default_user_root())
    ap.add_argument("--license", default="0xFFFFFFFF", help="licence mask written to the .header")
    args = ap.parse_args()
    mask = int(args.license, 0) & 0xFFFFFFFF
    print(f"user data root: {args.user_data_root}")
    for p in args.packages:
        print(os.path.basename(p))
        install(p, args.user_data_root, mask)
    print("done. Launch normally; the content enumerates from the user data root. If the game still treats it "
          "as unlicensed, add --license_mask=0xFFFFFFFF or use the DLC LICENSE cheat row (togglelicenseoverride).")


if __name__ == "__main__":
    main()
