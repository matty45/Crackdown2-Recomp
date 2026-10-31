# Performance notes and profiling

Detailed measurements moved out of the README on 2026-10-30. The short version is in README.MD under *Performance*.

## Measurements

Measured on the NUC (Ryzen 9 7940HS / Radeon 780M, Windows 11, D3D12, 1280x720 window, `--vsync=false`) in the Agency tutorial
room, turning the camera through twelve headings at one spot (`results/perf0c_*` vs `results/perf2c_*`):

| Setting | Facing the gate | Facing the plain walls |
| --- | --- | --- |
| Defaults | 35 FPS | 3.5-17 FPS |
| `--readback_memexport=false` | 36-45 FPS | 33-44 FPS |

The runtime copies every memexport (GPU-to-memory) result back to the CPU by default, which stalls the whole GPU pipeline
whenever the scene uses it. The game does not read those results on the CPU in anything observed so far, so the game defaults it off
(`ApplyGameDefaults` in `src/game_console.cpp`); the Options > Display **GPU READBACK** row and the F5 overlay expose the
switch, and the launcher (`tools/run_cd2.ps1`) passes `--readback_memexport=true` if you give it `-Readback`.

Second switch, found by profiling (see below): the runtime's `clear_memory_page_state` cvar (default on) forgets every
CPU-uploaded page of GPU shared memory at the end of each frame, so the whole scene's vertex and index data (~20 MB in the
tutorial room, ~800 MB/s) is copied to the GPU again every frame. The CPU write-watch already catches real changes, and
the game renders identically with it off, so it is a game default too (`-PageRefresh` on the launcher turns it back
on); the Options > Display **GPU PAGE REFRESH** row and the F5 overlay expose it as well. Same spot, same stepped
turn, stock SDK: 37.5 FPS with it on, 42.2 FPS with it off.

Where the rest goes: with both switches off the frame is bound by the SDK's "GPU Commands" thread, which runs at 100%
translating the game's ~6,000 draw calls per frame (Tracy capture `results/perf10prof`). The guest render thread spends
two thirds of its time waiting on it (`D3D_CDevice_BlockOnFence`), and the game's own loop runs at 140-250 Hz, so neither
the recompiled CPU code nor the GPU itself is the limit. Per-draw costs on that thread: shared-memory range requests
(uploads) ~23%, register writes ~29% before the SDK patch below, primitive processing ~10%, submission ~12%, AMD driver
~10%. Reducing that per-draw cost is SDK work; a patch that writes type-0 register ranges in bulk (as upstream Xenia does)
cut register handling from 29% to 11% of the thread and is kept under `patches/rexglue-sdk/`.

**Dense city zones** are a different, harder case. On an RTX 3050 Ti laptop (Ryzen 9 5900HS) the open city runs at the
game's 30 FPS cap, but the densest districts drop to 22-24 FPS whichever way the GPU is configured. The profile there is
flat: ~15,000 draw calls per frame at ~1.6 µs of backend work each (bindings, primitive processing, render-target and
texture lookups, vertex-fetch residency - no single stage above 20%), plus ~0.6 µs per draw of command-stream parsing,
on one core that the laptop's shared power budget holds at ~3.7 GHz. The GPU is idle-waiting, the frame-open fence wait
is 0.2 ms, and process priority makes no difference; it is single-thread CPU throughput, and the Xenia-derived backend
cannot be parallelised without a redesign. Everything that reduces draw calls visibly was measured: the LOD transition
bias, occlusion toggles, crowd density, far-car culling and memexport readback (synchronous or the asynchronous batched
variant in patch 0002) leave the draw count unchanged; only the engine's own `togglelod4env`, which stops drawing the
most distant environment tier, cuts it enough (to ~500 draws) to hold 30. That is what the **PERFORMANCE MODE** row (and
the F5 overlay / `--c2_performance_mode=true`) applies: a steady 30 in dense districts at the cost of far landmarks such
as the Agency tower, which only appear once you get closer. Off by default; a faster desktop CPU (~35-40% more
single-thread speed) is the other way to a locked 30 there.

Things that did not help on this hardware (all within ±2 FPS run-to-run noise): `--occlusion_query_enable=false`,
`--native_2x_msaa=false`, `--d3d12_bindless=false`, `--d3d12_tiled_shared_memory=false`,
`--d3d12_submit_on_primary_buffer_end=false`, a Release-configuration build of the game and SDK, and the game's own
crowd / depth-of-field / motion-blur / particle toggles. The game's `fastrender` console command gives ~46 FPS but skips
part of the lighting pass (flatter, brighter image), and `forcelod 2` simply stops drawing the room, so neither is a
usable setting. `--draw_resolution_scale_x/y=2` currently removes the D3D12 device at boot (`HRESULT 0x887A0001`), so
leave RENDER SCALE at 1X on D3D12 for now. The in-game `perfgraph` and `gputiming` console commands (cheat rows PERF
GRAPH / GPU TIMING) draw the game's own frame-time graphs for further digging.

## Profiling

Every non-Release SDK configuration (the `*-relwithdebinfo` presets) has Tracy zones, call-stack sampling and a
per-frame counter registry compiled in; the runtime just never switches them on. Two flags do:

* `--c2_perf_csv=<file>` writes one line per guest frame (frame time, draw calls, command-buffer stalls, texture and
  pipeline cache hits). `tools/perf_csv_summary.py <file> [window_s]` prints rolling averages, 1% lows and draws per
  frame. A healthy title screen is ~446 draws/frame; the Agency tutorial room is ~6,000.
* `--c2_profile=true` starts the Tracy listener on TCP 8086. Windows Firewall blocks it from other machines (and pops
  an allow/deny prompt on first use), so capture on the same machine: build `capture` from the SDK's
  `thirdparty/tracy` and run `tracy-capture -a 127.0.0.1 -o run.tracy -s 30 -f` while the game is at the spot you
  care about. `tools/tracy_sampdump` (built against the same Tracy tree, see its CMakeLists) dumps per-thread sampled
  hotspots and zone totals as text; the stock Tracy UI opens the file too. The prebuilt SDK DLLs ship without PDBs,
  so symbols inside `rexgpu-xenosrd.dll` only resolve if you put a from-source build (DLL + PDB) beside the exe.

## Stability notes

* The runtime's `InputSystem::RefreshDevices()` rebuilds its device list without locking on every XInput call, and the
  game polls input from several guest threads; a Windows run died during a city load inside that vector's destructor
  (STATUS_ILLEGAL_INSTRUCTION in rexruntimerd.dll). `src/hooks.cpp` now binds the game's `XamInputGetState` /
  `GetCapabilities` / `SetState` / `GetKeystrokeEx` calls to wrappers that serialize them through one mutex before
  forwarding to the runtime's originals.
