# Crackdown 2 Recomp

A native PC port of Crackdown 2 (Xbox 360) built with the [rexglue SDK](https://github.com/rexglue/rexglue-sdk): the
game's executable is statically recompiled to C++, the SDK provides the Xbox runtime and a GPU translation layer.

**Status (2026-10-30):** the whole game is playable on Windows. Linux and Android run it with the Vulkan backend
(experimental). Audio is unchanged from upstream.

| Platform | Graphics | State | Frame rate (game cap is 30) |
| --- | --- | --- | --- |
| Windows 10/11 x64 | Direct3D 12 | Playable start to finish | 30 over most of the city, 22-27 in the densest blocks (RTX 3050 Ti laptop) |
| Linux x64 | Vulkan | Playable, experimental | 30 in menus; 11-16 in the first gameplay area on Intel Iris Xe laptop graphics |
| Android arm64 | Vulkan | Playable with a gamepad, experimental | About 20 in the city on a Pixel 10 Pro, with PERFORMANCE MODE |

Downloads are on the [Releases](https://github.com/ImpetuousDanny/Crackdown2-Recomp/releases) page. The Windows build
is [preview-20261030.1](https://github.com/ImpetuousDanny/Crackdown2-Recomp/releases/tag/preview-20261030.1); Linux and
Android are [preview-20261030.2](https://github.com/ImpetuousDanny/Crackdown2-Recomp/releases/tag/preview-20261030.2).

**No game data is included.** You need your own disc dump and Title Update 5.

## Screenshots

RTX 3050 Ti laptop, 3440x1440 monitor, default settings.

| ASPECT RATIO = AUTO (21:9 on this monitor) | ASPECT RATIO = 16:9 (original framing, side bars) |
| --- | --- |
| ![City at 21:9](docs/screenshots/city_21x9.png) | ![City at 16:9 with side bars](docs/screenshots/city_16x9_on_ultrawide.png) |

![Rooftop at 21:9](docs/screenshots/rooftop_21x9.png)

![Over Pacific City in the Agency helicopter](docs/screenshots/helicopter_21x9.png)

Android: Pixel 10 Pro with a Razer Kishi V2, Vulkan backend, Keys to the City DLC.

![Pacific City on a Pixel 10 Pro](docs/screenshots/android_pixel10_city.png)

## Play it on Windows

1. Install [Python 3](https://www.python.org/downloads/windows/) (tick *Add python.exe to PATH*). It only runs the
   setup scripts.
2. Download `Crackdown2-Recomp-win-amd64.zip` from the **Releases** page and extract it anywhere, e.g.
   `C:\Games\Crackdown2`.
3. Dump your disc to an ISO and get the Title Update 5 file (hashes below), then in PowerShell from the extracted
   folder run:
   ```
   python tools\setup_game.py --iso <game.iso> --tu <TU5 file> [--dlc <package> ...]
   ```
   This extracts the disc and update, verifies the hashes, installs any DLC packages you own and records the paths.
4. Start the game:
   ```
   .\tools\run_cd2.ps1
   ```
   If PowerShell refuses to run scripts, run `.\tools\run_cd2.ps1 -DesktopShortcut` once from
   `powershell -ExecutionPolicy Bypass`; it puts a *Crackdown 2* shortcut on the desktop. `-Cheats` adds the cheat rows.
5. On the START screen press **Enter**. Everything else is in *Options > Display* (graphics, aspect ratio, input, cheats)
   and is saved to `crackdown2.toml` next to the exe when you exit.
6. Optional: `crackdown2-shadercache.zip` from the release removes first-run shader stutter. Extract it and start with
   `--cache_root="<path>\cache"`.

Requirements: Windows 10/11 x64, a Direct3D 12 GPU, about 2 GB of disk. On a laptop with two GPUs, assign
`crackdown2.exe` to the high-performance GPU in *Settings > System > Display > Graphics*. The intro videos need an
audio output device; without one the screen stays black until you press Enter.

## Play it on Linux

Needs an x86-64 distribution with glibc 2.38 or newer (Ubuntu 24.04, Linux Mint 22, Fedora 39 or later), a GPU with a
Vulkan 1.1 driver (Mesa or NVIDIA), Python 3, and X11 or Wayland.

1. Download `Crackdown2-Recomp-linux-x64.tar.gz` from the release and extract it:
   ```
   tar xzf Crackdown2-Recomp-linux-x64.tar.gz && cd Crackdown2-Recomp-linux-x64
   ```
2. Extract your disc image and Title Update 5 (same hashes as below):
   ```
   python3 tools/setup_game.py --iso <game.iso> --tu <TU5 file> [--dlc <package> ...]
   ```
   DLC goes to `~/.local/share/crackdown2`.
3. Start the game:
   ```
   ./tools/run_cd2.sh
   ```
   Extra flags are passed through, for example `./tools/run_cd2.sh --c2_fps_display=true --c2_performance_mode=true`.
   Keyboard and mouse are on as on Windows; `--no-keyboard` leaves only the gamepad.

The first run compiles shaders and is slow for a minute or two; the compiled shaders and the driver's pipeline cache are
kept for later runs.

## Play it on Android

Experimental. Needs a 64-bit Android device with Vulkan 1.1, 8 GB of RAM or more, about 8 GB free storage and a
gamepad (touch controls are not implemented). Tested on a Pixel 10 Pro (PowerVR GPU) with a Razer Kishi V2.

1. On a PC, extract the game with `python3 tools/setup_game.py --iso <game.iso> --tu <TU5 file> --dest cd2` (from the
   Linux or Windows download, or from this repository).
2. Install `Crackdown2-Recomp-android-arm64.apk` from the release (allow installing from your browser or file manager,
   or `adb install Crackdown2-Recomp-android-arm64.apk`). Start it once and close it, which creates its data folder.
3. Copy the extracted folders onto the device with [adb](https://developer.android.com/tools/releases/platform-tools):
   ```
   adb push cd2/assets /sdcard/Android/data/com.crackdown2.recomp/files/assets
   adb push cd2/tu5    /sdcard/Android/data/com.crackdown2.recomp/files/tu5
   ```
4. Recommended flags, one per line in `/sdcard/Android/data/com.crackdown2.recomp/files/args.txt`:
   ```
   --c2_performance_mode=true
   --audio_maxqframes=32
   ```
5. Start *Crackdown 2* from the launcher. The first loading screen takes a few minutes on the first run.

DLC: `python3 tools/dlc_install.py --user-data-root cd2/user <package> ...`, then
`adb push cd2/user/. /sdcard/Android/data/com.crackdown2.recomp/files/user/`. More in [docs/android.md](docs/android.md).

## Controls

* **Gamepad**: any SDL-recognised pad works; `--input_backend=xinput` selects XInput instead. Pad and keyboard are
  merged as player 1.
* **Keyboard and mouse** (on by default): WASD move, mouse look, left button fire, right button lock on, middle button
  zoom, Space jump, E melee / hold to pick up, Q enter or exit vehicle, Shift crouch, F pick up weapon, R reload,
  G grenade, Enter Start, Tab Back. Rebind in the **F4** overlay, or set `keybind_*` cvars (`--keybind_a="Space,LMB"`;
  `LMB`/`RMB`/`MMB` and `Shift+`/`Ctrl+`/`Alt+` prefixes are valid).
* **F5** overlay (settings and a developer-console prompt), **F6** releases or grabs the mouse, **F3** SDK debug overlay.

## Settings

All rows live on *Options > Display*, drawn by the game's own menu:

* Graphics: V-SYNC, FULLSCREEN, FPS COUNTER, ASPECT RATIO (AUTO, 16:9, 16:10, 21:9, 32:9), RESOLUTION (window height),
  RENDER SCALE, 2X MSAA, ANTI-ALIASING, ANISOTROPIC FILTER, UPSCALING FILTER, GPU READBACK, GPU PAGE REFRESH,
  PERFORMANCE MODE, EXIT, APPLY & RESTART.
* Input: KEYBOARD AND MOUSE, MOUSE LOOK, MOUSE SENSITIVITY, GAMEPAD DRIVER.
* With `-Cheats`: GOD MODE, INFINITE AMMO, ALL WEAPONS, MAX SKILLS, TIME OF DAY, SPAWN ENEMY, WARP, FLY CAM, DLC
  LICENSE and more, each running one of the retail developer console's ~730 commands
  ([docs/console_commands.md](docs/console_commands.md)). `--c2_console_startup="cmd1;cmd2"` runs commands at boot,
  **F8** runs them again.

Aspect ratio is real field of view, not stretching: the game lays out its projection and HUD from the video mode the
recomp reports. AUTO matches your monitor; 16:9 keeps the original framing with side bars. Settings are written to
`crackdown2.toml` on exit; command-line flags override it.

Defaults the game applies: v-sync and fullscreen on, 2x MSAA, no post AA, 16x anisotropic filtering, GPU readback and
page refresh off (they cost most of the frame rate), mouse sensitivity 3.

## Known issues

* RENDER SCALE above 1X removes the D3D12 device at boot. Leave it at 1X; if a saved `crackdown2.toml` has it, delete
  the `draw_resolution_scale_*` lines.
* Dense city blocks dip below 30 FPS on laptop CPUs: the backend submits ~12,000 draws per frame on one thread.
  PERFORMANCE MODE holds 30 by not drawing the most distant environment tier, so far landmarks pop in. Details and
  measurements in [docs/performance.md](docs/performance.md).
* Vulkan (Linux, Android) is slower than Direct3D 12 on the same scene: the command thread translating the game's draws
  is the limit, not the GPU. The Windows release still uses Direct3D 12; a Vulkan option on Windows needs the patched
  plugin and has not been tested yet.
* Android: no touch controls; the APPLY & RESTART row quits instead of restarting; audio can crackle without
  `--audio_maxqframes=32`.

## DLC

Marketplace packages are extracted into the user data root (`Documents\crackdown2` on Windows) by
`tools\dlc_install.py <package> [...]` or `setup_game.py --dlc`. Supported: Toy Box, Deluge and Pre-Order Armor (hashes
below). If a pack shows as unlicensed, use the DLC LICENSE cheat row or `--license_mask=0xFFFFFFFF`.

## Hashes

| File | SHA-256 |
| --- | --- |
| `default.xex` | `8959C449E382661D29B8EA479C685F506CD5BD3ECA40B3D73A51CC10F281069F` |
| Title Update 5 (`xexp`) | `A5E49FC1FF7F6F65E6F95A7B5C4B9392BB9E38674D1237AC0E2F0149D05929D7` |
| Toy Box Pack `856014F705032E789E4A6DBD2546F470B06ED71F4D` | `CF679BB4A061F9C7319EB1D5E4297888A1AB52B73436DC0B08C47F0528C774FD` |
| Deluge Pack `BD0C27EFE61BEE10F176F3A624F8A851224A89694D` | `A1064677C4A756C4C82DC79CDA60622F15A19E14393AE661E1CE4B9CCC6AD480` |
| Pre-Order Armor `ACE4E65BC7BA561F3A27C1A5390B5904CB6C73EB4D` | `1EE257B70EC9B61BF8B7FAC47579D9982A7BCDD1D47080260ECBD1F4CD09E372` |

## Vulkan fixes

The rexglue 0.10.0 Vulkan backend rendered Crackdown 2 dark or colour-tinted on every GPU, and on the Pixel's PowerVR
GPU the intro videos were grey and the gameplay screen was red. These SDK patches fix it (details and measurements in
[patches/rexglue-sdk/README.md](patches/rexglue-sdk/README.md)):

| Patch | Fix |
| --- | --- |
| [0006](patches/rexglue-sdk/0006-spirv-texture-exp-adjust-from-fetch-word-3.patch) | Shader translator read the texture exponent bias from the wrong fetch-constant word: dark, tinted scenes on every GPU |
| [0007](patches/rexglue-sdk/0007-vulkan-write-texture-descriptors-one-binding-at-a-time.patch) | PowerVR driver bug with descriptor writes spanning several bindings: grey and green intro videos |
| [0008](patches/rexglue-sdk/0008-vulkan-stencil-bit-transfer-from-depth-source.patch) | Stencil copy from a depth buffer wrote 0xFF without `VK_EXT_shader_stencil_export`: red screen in game |
| [0009](patches/rexglue-sdk/0009-posix-waits-sleep-instead-of-spinning.patch) | Linux/Android thread waits spun at 100% CPU; they now block and wake on signal |
| [0010](patches/rexglue-sdk/0010-vulkan-shrink-render-area-to-used-region.patch) | Render passes cover only the region drawn, halving tile memory traffic on mobile GPUs |
| [0011](patches/rexglue-sdk/0011-vulkan-persistent-driver-pipeline-cache.patch) | Driver pipeline cache saved between runs |

The Linux and Android release builds include all of them.

## Building

Requirements: [rexglue SDK 0.10.0](https://github.com/rexglue/rexglue-sdk/releases/tag/v0.10.0), CMake 3.25+, Ninja,
LLVM/Clang 20+, Python 3, and on Windows the VS 2022 Build Tools with a Windows SDK (run from a `vcvars64` prompt).

1. Extract the disc and title update into `assets\` (`python tools\setup_game.py --iso <iso> --tu <TU5> --dest .`).
2. Configure and build; codegen runs as the first build step:
   ```
   cmake --preset win-amd64-relwithdebinfo -DCMAKE_PREFIX_PATH=<sdk-folder>
   cmake --build --preset win-amd64-relwithdebinfo
   ```
   Linux: `linux-amd64-release` with `-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld -DREXSDK_DIR=<patched rexglue-sdk>` (the
   Vulkan fixes are in the SDK patches, so build the SDK from source). Android: `REXSDK_DIR=<patched rexglue-sdk>
   tools/build_android.sh` (NDK 28, JDK 17; see [docs/android.md](docs/android.md)).
3. Run with `.\tools\run_cd2.ps1` (or `crackdown2 --game_data_root=<assets> --update_data_root=<TU5 folder>
   --gpu_plugin=xenos`). The game must start from an interactive desktop session.

The keyboard/mouse, settings-saving, readback, Android and Vulkan fixes live in the SDK: apply
`patches/rexglue-sdk/*.patch` in order to a v0.10.0 checkout and build it (see
[patches/rexglue-sdk/README.md](patches/rexglue-sdk/README.md)). The build runs codegen with
`REX_MAX_JUMP_TABLE_ENTRIES=519`, which the game needs for one 518-entry switch table.

## More documentation

* [docs/android.md](docs/android.md): the Android port, device notes and building the APK.
* [docs/performance.md](docs/performance.md): measurements, what was tried, profiling with Tracy and the perf CSV.
* [docs/native_menu.md](docs/native_menu.md): how the extra rows are injected into the game's Scaleform menus.
* [docs/console_commands.md](docs/console_commands.md): the retail developer console commands.
* [patches/rexglue-sdk/README.md](patches/rexglue-sdk/README.md): the SDK patch series.
