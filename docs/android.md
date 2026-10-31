# Android build (experimental)

Work in progress on the `feature/android` branch: Crackdown 2 Recomp as an
arm64-v8a APK, built with the Android NDK and hosted by SDL3's activity, using
the rexglue Vulkan backend. Research notes first, then the state of the port.

## What the port is made of

| Piece | Status |
| --- | --- |
| Recompiled game code (`generated/`, 256 translation units, ~270 MB of C++) | Portable. It uses the SDK's `simde`-based PowerPC vector helpers, which map SSE to NEON on arm64. One guest symbol (`__errno`) clashed with Bionic and is renamed `cd2___errno` in `default_functions.toml`. |
| rexglue SDK runtime (`librexruntime.so`) | Had Android hooks (platform macro, ashmem memory, Vulkan Android surface) but no build path. Patched: see *SDK changes*. |
| GPU plugin (`librexgpu-xenos.so`, Vulkan) | Builds for Android. The dark/tinted output that the Vulkan backend showed on every GPU (Intel Linux, AMD Windows, PowerVR) was a shader-translator bug, fixed by SDK patch 0006; with it the title screen and gameplay match D3D12 on Linux. On the Pixel 10 Pro (PowerVR) SDK patch 0007 is also needed; with both, the intro movies and title screen render correctly. |
| Windowing, input, lifecycle | SDL3 for Android (Java `SDLActivity` + `libSDL3.so`); game `GameActivity` passes data paths as arguments. Touch controls do not exist yet: use a Bluetooth or USB gamepad. |
| Audio | SDL3 audio on Android (AAudio/OpenSL inside SDL). Untested. |
| Build | `tools/build_android.sh` runs CMake with the NDK toolchain (SDK in-tree via `REXSDK_DIR`), copies the `.so` files into `android/app/src/main/jniLibs/arm64-v8a` and runs Gradle. Codegen stays a host step: `generated/default` must exist from a PC build. |

## Prior art

* [NFSMW Android Evolved](https://github.com/codepdbh/nfsmw-android) and its
  [NFS Carbon sibling](https://github.com/codepdbh/NFS-CARBON-360-ANDROID-RECOMP)
  carry rexglue 0.10.0 to Android (GPL-3.0). Their notes were the map for which
  SDK pieces need Android branches (SDL main, Bionic fibers, libc++ gaps,
  logcat sink, app folder, plugin loading by soname, surface lifecycle). The
  code here is written against the same rexglue sources rather than copied.
  Their key finding: the emulated Xenos GPU path ran at 1-3 FPS on Switch, so
  they wrote a native renderer for their game. Crackdown 2 has no such
  renderer; this port stands or falls with the Xenos Vulkan backend on mobile.
* Xenia Android ports ([xeo](https://github.com/libaerto/xeo), successor of
  xenia-android) run the same GPU emulation approach on Adreno; Pixel 10's
  PowerVR driver has had Vulkan issues in emulators.

## Expectations

* CPU: the Windows build is bound by single-thread draw submission (~12k draws
  per frame in dense city). A Tensor G5 or Snapdragon 8-class core scores
  about as high per thread as the Ryzen 9 5900HS laptop used for the Windows
  figures, so the city dip would be similar if everything else were equal;
  thermals and the Vulkan backend's own cost decide the rest. Tutorial and
  menus should be fine.
* GPU: needs Vulkan 1.1+ with the features the Xenos backend asks for
  (fragment shader interlock is optional). Mali and PowerVR are untested.
* Memory: the runtime reserves the 4 GB guest address space; 64-bit Android
  has the virtual space, and ashmem/ASharedMemory backs the mapped views.
  A device with 8 GB RAM or more is advisable.

## SDK changes (patch 0003, Android)

* CMake: `android-arm64` platform, no host tools (codegen/CLI) when
  cross-compiling, 16 KiB page alignment, SDL3 shared, no X11/Wayland,
  `-fexperimental-library` + `libc++experimental` for `std::jthread`.
* `fiber_android.cpp`: AAPCS64 context switch (Bionic has no
  `makecontext`/`swapcontext`); guest fibers need it.
* libc++ gaps: float `std::from_chars` fallback, `clock_time_conversion`.
* `surface_android.cpp`: ANativeWindow surface from SDL; window reattaches the
  presenter after the activity returns from the background.
* Entry point: `SDL_main` through SDL's activity; the single registered app
  is picked (`WindowedApp::GetSoleCreator`).
* `GetExecutableFolder()` honours `REX_APP_FOLDER` (settings, logs, pipeline
  cache live in the app's files directory); GPU plugin loaded by soname;
  logcat sink (tag `rexglue`); `AndroidInitialize` for memory and threads.

## First runs (Pixel 10 Pro, 2026-10-30)

* The runtime starts, maps the guest address space, loads the XEX and the title
  update, creates a Vulkan swapchain on the PowerVR driver and runs guest code
  (file I/O, audio endpoint, shader pipelines) from `SDLActivity`.
* First blocker: a `brk` trap while loading the game database. The animation
  attribute loader's switch table has 518 entries but the recompiler capped
  jump tables at 512 (`max_jump_table_entries` is a codegen cvar that SDK
  0.10.0 does not read from the manifest; SDK patch 0005 fixes that, and
  `tools/build_android.sh` also passes it through `REX_MAX_JUMP_TABLE_ENTRIES`).
  Attribute ids 512-516 occur in the game data, so the Windows build carries
  the same hole and should be regenerated with the fix.
* Pointer tagging: the manifest sets `allowNativeHeapPointerTagging="false"`
  so host pointers keep a clean top byte (the runtime mixes host pointers and
  guest addresses in places); not yet shown to matter.
* Rendering: the first runs showed only a very dark logo on black. That was
  not the PowerVR driver: the SDK's SPIR-V translator read a texture's
  exponent bias from the wrong fetch-constant word, so any texture with a
  LOD bias was scaled by a large power of two (SDK patch 0006). The same bug
  darkened or tinted the Vulkan backend on Intel and AMD desktops.
* Intro movies: after that fix the title screen was right but the 1080p
  intro movies and the city cutscene came out flat grey with green and
  magenta. The decoded frames were correct; the PowerVR driver mishandles a
  descriptor write that spans several consecutive bindings, so all three YUV
  planes sampled the same texture (SDK patch 0007 writes one binding at a
  time). Also: `tools/build_android.sh` now packs the GPU plugin from the
  SDK's output folder; the copy beside the game was not rebuilt when only
  the plugin changed.
* In the city: the whole frame (HUD included) was red. The backend's
  per-bit stencil copy (used because PowerVR has no stencil export) never
  tested the stencil bits for depth sources, so stencil became 0xFF and the
  game's depth-as-colour reinterpretation put it in red (SDK patch 0008).
* State after these fixes (Pixel 10 Pro, Razer Kishi V2 over USB-C): intro
  movies, menus, DLC (installed with `tools/dlc_install.py` into
  `files/user`) and the open city render correctly; about 20 FPS with
  `--c2_performance_mode=true`. `--audio_maxqframes=32` in `files/args.txt`
  for audio crackle. The in-game restart option quits on Android.
* Performance (Pixel 10 Pro, city): about 20 FPS. `perf_event` is blocked on
  this production build even with `security.perf_harden=0`, so the game has an
  opt-in signal sampler: `--c2_cpu_sample_after=150 --c2_cpu_sample_seconds=15`
  writes per-thread hot addresses and runtime/game callers to
  `files/user/cpu_samples.txt` (symbolise with llvm-symbolizer / llvm-nm against
  the unstripped `libmain.so` and `librexruntime.so`). It showed two guest
  threads spinning in the SDK's `WaitMultiple` (fixed, SDK patch 0009); after
  that the main game thread spends ~75% of its time in `D3D::BlockOnFence`, i.e.
  waiting for the GPU, and the GPU sits at its top clock (1094 MHz). FIFO
  presentation, native MSAA off and render-area shrinking (SDK patch 0010) did
  not move the displayed rate; the remaining cost is the game's ~3,000 draws per
  frame through translated Xenos shaders.
* Orientation: SDL re-applies its own orientation when the window is created,
  which turned the phone to portrait; `GameActivity` overrides
  `setOrientationBis` to force landscape.

## Building and installing

```
tools/build_android.sh            # configure + natives + APK
tools/build_android.sh install    # adb install
```

`REXSDK_DIR` points at the rexglue-sdk source tree (default `../rexglue-sdk`) with every patch from
`patches/rexglue-sdk/` applied; `BUILD_DIR` overrides the build folder (default `out/build/android-arm64`).
The APK is signed with the debug key so it can be sideloaded.

Game data goes to the app's external files directory (no permission needed):

```
adb push assets        /sdcard/Android/data/com.crackdown2.recomp/files/assets
adb push tu5_extracted /sdcard/Android/data/com.crackdown2.recomp/files/tu5
```

Extra command-line flags: one per line in `.../files/args.txt`. Logs:
`.../files/user/crackdown2.log` and `adb logcat -s rexglue Crackdown2 SDL`.
