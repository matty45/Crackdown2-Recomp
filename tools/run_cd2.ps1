# Launch the Crackdown 2 recomp on Windows.
#   .\tools\run_cd2.ps1 [-Config release|relwithdebinfo|debug] [-Assets <path>] [-Update <path>] [-Backend any|d3d12|vulkan]
#                       [-RenderPath rtv|rov]
#   (-Assets/-Update default to the paths tools\setup_game.py wrote to cd2_game.json)
#                       [-Cheats] [-Readback] [-PageRefresh] [-VSync] [-NoKeyboard] [-PerformanceMode] [-DesktopShortcut]
#                       [extra args...]
# -Cheats   enables the hidden cheat rows at the end of Options > Display (--c2_cheats=true).
# -Readback keeps the runtime's GPU memexport readback on (the game defaults it off: 3-10x faster, see README "Performance").
# -PageRefresh keeps the runtime's per-frame GPU page-state refresh on (default off: the game re-uploads ~20 MB of
#           unchanged vertex data every frame with it on, see README "Performance").
# -NoKeyboard leaves keyboard/mouse gamepad emulation off (default on: --mnk_mode --mnk_mouse=true, so the
#           "press START" screen and menus work without a controller; a real controller still works alongside).
# -VSync    keeps v-sync on (default off so the frame rate is not capped at the display's refresh / 2).
# -PerformanceMode hides the most distant environment tier (the game's togglelod4env) so dense city districts
#           hold a steady 30 FPS on slower CPUs; far landmarks such as the Agency tower only appear up close.
#           Same as the Options > Display PERFORMANCE MODE row (--c2_performance_mode=true).
# -DesktopShortcut creates a "Crackdown 2" shortcut on the desktop that runs this script with the other
#           switches you gave (via powershell -ExecutionPolicy Bypass), then exits without starting the game.
# -RenderPath picks the D3D12 render-target path: "rtv" (fast, default on AMD/NVIDIA) or "rov"
#           (accurate EDRAM depth/stencil - fixes lights leaking through walls, but costlier). Leave
#           unset to let the backend choose. See README "Performance".
# -Config defaults to release (optimised; strips the profiling/perf-counter instrumentation that the
#           relwithdebinfo build compiles in). Use -Config relwithdebinfo for --c2_perf_csv / Tracy.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Config = "release",
    [string]$Assets = "",
    [string]$Update = "",
    [string]$Backend = "any",
    [string]$RenderPath = "",
    [switch]$Cheats,
    [switch]$Readback,
    [switch]$PageRefresh,
    [switch]$VSync,
    [switch]$NoKeyboard,
    [switch]$PerformanceMode,
    [switch]$DesktopShortcut,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]]$Rest
)
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
# tools\setup_game.py records the extracted disc and title update paths here.
$cfgPath = Join-Path $root "cd2_game.json"
if (Test-Path $cfgPath) {
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
    if ($Assets -eq "" -and $cfg.assets) { $Assets = $cfg.assets }
    if ($Update -eq "" -and $cfg.update) { $Update = $cfg.update }
}
if ($Assets -eq "") { $Assets = Join-Path $root "assets" }
if (-not (Test-Path (Join-Path $Assets "default.xex"))) {
    Write-Error "No default.xex in $Assets. Run: python tools\setup_game.py --iso <disc.iso> --tu <title update> [--dlc <packages>]"; exit 1
}
$build = Join-Path $root "out\build\win-amd64-$Config"
$exe = Join-Path $build "crackdown2.exe"
# Release zips ship crackdown2.exe next to this script's parent folder instead of under out\build.
if (-not (Test-Path $exe) -and (Test-Path (Join-Path $root "crackdown2.exe"))) { $exe = Join-Path $root "crackdown2.exe" }
if (-not (Test-Path $exe)) { Write-Error "Executable not found: $exe (build the win-amd64-$Config preset first, or run from an extracted release)"; exit 1 }
$args = @("--game_data_root=$Assets", "--gpu_plugin=xenos", "--c2_gpu_backend=$Backend")
if ($Update -ne "") { $args += "--update_data_root=$Update" }
# The game itself defaults readback / page refresh / v-sync to off (src/game_console.cpp
# ApplyGameDefaults) and remembers menu changes in crackdown2.toml, so only pass the
# opposite when asked; a command-line flag would override the saved setting every launch.
if ($Readback) { $args += "--readback_memexport=true" }
if ($PageRefresh) { $args += "--clear_memory_page_state=true" }
if ($VSync) { $args += "--vsync=true" }
if ($RenderPath -ne "") { $args += "--render_target_path_d3d12=$RenderPath" }
if (-not $NoKeyboard) { $args += "--mnk_mode", "--mnk_mouse=true" }
if ($Cheats) { $args += "--c2_cheats=true" }
if ($PerformanceMode) { $args += "--c2_performance_mode=true" }
$args += $Rest
Write-Host "Running: $exe $($args -join ' ')"

if ($DesktopShortcut) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $lnk = Join-Path $desktop "Crackdown 2.lnk"
    $switches = @()
    if ($Config -ne "release") { $switches += "-Config $Config" }
    if ($Assets -ne "") { $switches += "-Assets `"$Assets`"" }
    if ($Update -ne "") { $switches += "-Update `"$Update`"" }
    if ($Backend -ne "any") { $switches += "-Backend $Backend" }
    if ($RenderPath -ne "") { $switches += "-RenderPath $RenderPath" }
    foreach ($sw in "Cheats","Readback","PageRefresh","VSync","NoKeyboard","PerformanceMode") {
        if ((Get-Variable $sw).Value) { $switches += "-$sw" }
    }
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut($lnk)
    $s.TargetPath = (Get-Command powershell).Source
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" " + ($switches -join " ")
    $s.WorkingDirectory = Split-Path $PSCommandPath -Parent | Split-Path -Parent
    $s.IconLocation = "$exe,0"
    $s.Description = "Crackdown 2 (PC recompilation)"
    $s.Save()
    Write-Host "Created $lnk"
    exit 0
}
& $exe @args
