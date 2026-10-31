#!/usr/bin/env python3
"""One-shot game setup for the Crackdown 2 recomp: point it at your disc image, Title Update 5 and any DLC
packages, and it extracts/verifies everything and records the paths so `tools/run_cd2.ps1` (or the
executable) runs without further arguments.

    python tools/setup_game.py --iso "Crackdown 2.iso" --tu "tu5.xexp-container" [--dlc pack1 pack2 ...]

Each input may also be a folder that is already extracted (then it is only linked, not copied):
    python tools/setup_game.py --iso D:\\cd2\\assets --tu D:\\cd2\\tu5

What it does:
  1. Extracts the XDVDFS disc image to <dest>/assets (tools/xdvdfs_extract.py), or uses the folder you gave.
  2. Extracts the STFS title-update container to <dest>/tu5 (tools/stfs_extract.py), or uses the folder you gave,
     and copies default.xexp next to assets/default.xex (codegen applies it from there).
  3. Checks the SHA-256 of default.xex and default.xexp against the known-good values from the README.
  4. Checks each DLC package against the README hashes (tools/verify_dlc.py) and installs it into the runtime's
     user data root (tools/dlc_install.py).
  5. Writes cd2_game.json in the project/release root with the assets and update paths, which run_cd2.ps1 reads
     when -Assets / -Update are not given.

Only pure Python is used; nothing from the disc is copied anywhere except <dest>.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

KNOWN_HASHES = {
    "default.xex": "8959c449e382661d29b8ea479c685f506cd5bd3eca40b3d73a51cc10f281069f",
    "default.xexp": "a5e49fc1ff7f6f65e6f95a7b5c4b9392bb9e38674d1237ac0e2f0149d05929d7",
}

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_tool(name, *args):
    cmd = [sys.executable, "-I", os.path.join(TOOLS, name), *args]
    print("  >", " ".join(cmd))
    subprocess.run(cmd, check=True)


def find_file(folder, filename):
    for dirpath, _, files in os.walk(folder):
        for f in files:
            if f.lower() == filename:
                return os.path.join(dirpath, f)
    return None


def check_hash(path, name, skip):
    if skip or not path or not os.path.isfile(path):
        return
    got = sha256(path)
    want = KNOWN_HASHES[name]
    if got == want:
        print(f"  OK   {name} matches the known-good hash")
    else:
        print(f"  WARN {name} hash {got} differs from the expected {want}.")
        print("       This is not the build the recomp was generated from; expect it not to run.")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iso", required=True, help="disc image (.iso) or an already extracted game folder")
    ap.add_argument("--tu", required=True, help="Title Update 5 container or an already extracted update folder")
    ap.add_argument("--dlc", nargs="*", default=[], help="DLC packages (LIVE/PIRS files) to install")
    ap.add_argument("--dest", default=os.path.join(ROOT, "game"),
                    help="where to extract (default: <project>/game)")
    ap.add_argument("--skip-hash", action="store_true", help="do not verify the executable hashes")
    ap.add_argument("--force", action="store_true", help="re-extract even if the destination already has files")
    args = ap.parse_args()

    os.makedirs(args.dest, exist_ok=True)

    # 1. Disc.
    print("[1/5] Game disc")
    if os.path.isdir(args.iso):
        assets = os.path.abspath(args.iso)
        print(f"  using existing folder {assets}")
    else:
        assets = os.path.join(os.path.abspath(args.dest), "assets")
        if os.path.isfile(os.path.join(assets, "default.xex")) and not args.force:
            print(f"  {assets} already extracted (use --force to redo)")
        else:
            os.makedirs(assets, exist_ok=True)
            run_tool("xdvdfs_extract.py", os.path.abspath(args.iso), assets)
    xex = os.path.join(assets, "default.xex")
    if not os.path.isfile(xex):
        sys.exit(f"default.xex not found under {assets}; is this the right disc?")

    # 2. Title update.
    print("[2/5] Title Update 5")
    if os.path.isdir(args.tu):
        update = os.path.abspath(args.tu)
        print(f"  using existing folder {update}")
    else:
        update = os.path.join(os.path.abspath(args.dest), "tu5")
        if find_file(update, "default.xexp") and not args.force:
            print(f"  {update} already extracted (use --force to redo)")
        else:
            os.makedirs(update, exist_ok=True)
            run_tool("stfs_extract.py", os.path.abspath(args.tu), update)
    xexp = find_file(update, "default.xexp")
    if not xexp:
        sys.exit(f"default.xexp not found under {update}; is this the Crackdown 2 title update?")
    target_xexp = os.path.join(assets, "default.xexp")
    if os.path.abspath(xexp) != os.path.abspath(target_xexp):
        if not os.path.isfile(target_xexp) or args.force or sha256(target_xexp) != sha256(xexp):
            shutil.copy2(xexp, target_xexp)
            print(f"  copied default.xexp next to default.xex")
        else:
            print("  default.xexp already beside default.xex")

    # 3. Hashes.
    print("[3/5] Verifying executables")
    check_hash(xex, "default.xex", args.skip_hash)
    check_hash(target_xexp, "default.xexp", args.skip_hash)

    # 4. DLC.
    print("[4/5] DLC")
    if args.dlc:
        pkgs = [os.path.abspath(p) for p in args.dlc]
        if not args.skip_hash:
            r = subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "verify_dlc.py"), *pkgs])
            if r.returncode != 0:
                print("  WARN a DLC package did not match a known-good hash (see above); installing it anyway")
        run_tool("dlc_install.py", *pkgs)
    else:
        print("  none given (add --dlc <package> ... later at any time)")

    # 5. Record the paths.
    print("[5/5] Recording paths")
    cfg = {"assets": assets, "update": update}
    cfg_path = os.path.join(ROOT, "cd2_game.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"  wrote {cfg_path}")
    print()
    print("Done. Start the game with:")
    if os.name == "nt":
        print(r"  .\tools\run_cd2.ps1")
    else:
        print("  ./tools/run_cd2.sh")


if __name__ == "__main__":
    main()
