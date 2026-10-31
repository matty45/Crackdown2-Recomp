#!/usr/bin/env bash
# Start Crackdown 2 on Linux.
#
#   tools/run_cd2.sh [--assets DIR] [--update DIR] [--no-keyboard] [extra game flags...]
#
# Keyboard and mouse gamepad emulation is on (--mnk_mode --mnk_mouse=true) as in
# tools/run_cd2.ps1; --no-keyboard leaves it off for gamepad-only play.
#
# Without --assets / --update the paths come from cd2_game.json, written by
# tools/setup_game.py. Extra arguments are passed to the game, e.g.
# --c2_fps_display=true or --c2_performance_mode=true.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"

assets=""
update=""
keyboard=1
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --assets) assets="$2"; shift 2 ;;
    --update) update="$2"; shift 2 ;;
    --no-keyboard) keyboard=0; shift ;;
    *) args+=("$1"); shift ;;
  esac
done

if [ -z "$assets" ] || [ -z "$update" ]; then
  if [ ! -f "$HERE/cd2_game.json" ]; then
    echo "No cd2_game.json: run 'python3 tools/setup_game.py --iso <game.iso> --tu <TU5 file>' first," >&2
    echo "or pass --assets <extracted disc> --update <extracted TU5>." >&2
    exit 1
  fi
  read -r json_assets json_update < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c["assets"], c["update"])' "$HERE/cd2_game.json")
  assets="${assets:-$json_assets}"
  update="${update:-$json_update}"
fi

# The release puts the executable and its libraries in the root folder; a
# source build keeps them in out/build/<preset>.
exe="$HERE/crackdown2"
if [ ! -x "$exe" ]; then
  exe="$(ls -d "$HERE"/out/build/*/crackdown2 2>/dev/null | head -1 || true)"
fi
if [ -z "$exe" ] || [ ! -x "$exe" ]; then
  echo "crackdown2 executable not found next to tools/ or in out/build/" >&2
  exit 1
fi

if [ "$keyboard" = 1 ]; then
  args=(--mnk_mode --mnk_mouse=true ${args[@]+"${args[@]}"})
fi

cd "$(dirname "$exe")"
export LD_LIBRARY_PATH="$(dirname "$exe")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$exe" --game_data_root="$assets" --update_data_root="$update" --gpu_plugin=xenos ${args[@]+"${args[@]}"}
