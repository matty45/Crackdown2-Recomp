#!/usr/bin/env bash
# Pack a Linux release: tools/package_linux.sh <build dir> <rexglue-sdk source dir> <output dir>
# The GPU plugin is not a link dependency of the game, so it (and the runtime)
# are taken from the SDK's own output folder, not the copy in the build dir.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$1"; SDK="$2"; OUT="$3"
NAME=Crackdown2-Recomp-linux-x64
STAGE="$OUT/$NAME"
STRIP="${STRIP:-$(command -v llvm-strip || command -v strip)}"
rm -rf "$STAGE"; mkdir -p "$STAGE/tools" "$STAGE/patches/rexglue-sdk"
cp "$BUILD/crackdown2" "$STAGE/"
cp "$SDK/out/linux-amd64/librexruntime.so" "$SDK/out/linux-amd64/librexgpu-xenos.so" "$STAGE/"
"$STRIP" --strip-unneeded "$STAGE/crackdown2" "$STAGE"/*.so
for f in run_cd2.sh setup_game.py xdvdfs_extract.py stfs_extract.py dlc_install.py verify_dlc.py; do
  cp "$ROOT/tools/$f" "$STAGE/tools/"
done
cp "$ROOT/README.MD" "$STAGE/"
cp "$ROOT"/patches/rexglue-sdk/*.patch "$ROOT/patches/rexglue-sdk/README.md" "$STAGE/patches/rexglue-sdk/"
(cd "$OUT" && tar czf "$NAME.tar.gz" "$NAME" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
ls -la "$OUT/$NAME.tar.gz"
