// crackdown2 - bridge to the game's own developer console.
//
// Crackdown 2 ships its retail build with the Ruffian developer console intact:
// ~730 commands ("god", "infiniteammo", "TeleportPlayer x y z", "summon <proto>",
// "todsetphase", "setfps", "perfgraph", ...). docs/console_commands.md lists
// them. The console object lives at Core+2804 and commands are executed by
// Console_Execute(console, const wchar_t* line, context) = sub_825CE628, where
// context is the local player (+1352) or 0 before a game is loaded.
//
// Commands must run on a guest thread with a live PPCContext, so host code
// queues them and the override of RWS_MainLoop_Poll (the game's per-frame poll)
// drains the queue on the game thread.

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <rex/ppc.h>

namespace c2 {

// Provide the action that cleanly shuts the game down. The app wires this to
// close its main window on the UI thread, which is what stops the guest, audio
// and GPU threads (RequestDeferredQuit alone bypasses that OnClosing path and
// leaves the process hanging). Called once the window exists, from
// Crackdown2App::OnCreateDialogs.
void SetQuitHandler(std::function<void()> handler);

// Ask the app to shut down cleanly (flushes the shader cache and exits). Safe
// from the game thread; the handler defers the window close to the UI thread.
void RequestQuit();

// Save the user-changed cvars to <exe>/crackdown2.toml (done on quit/restart).
void SaveSettings();
// Derive the guest video mode and window size from c2_aspect_ratio and the
// RESOLUTION preset. Call before the window and the guest exist (OnPreSetup).
void ApplyAspectRatio();
// Apply this game's preferred defaults (vsync/readback/page refresh off) to
// cvars nothing else has set. Call once the GPU plugin's cvars exist.
void ApplyGameDefaults();

// Save the current cvars to crackdown2.toml and relaunch the game (so
// restart-only display settings take effect), then quit this instance. The
// relaunch waits for this process to exit first. Windows only; elsewhere it
// just quits.
void RequestRestart();

// Run a console command right now on the calling guest thread.
bool ExecConsoleCommand(PPCContext& ctx, uint8_t* base, const std::string& command);

// Queue a command to run on the game thread at the next tick. Safe from any
// thread (ImGui overlays, key binds, ...).
void QueueConsoleCommand(const std::string& command);

// Queue every ';'-separated command of --c2_console_startup (bound to F8).
void RunStartupCommands();

// True once the game has created its console (after Core_Init).
bool ConsoleReady();

}  // namespace c2
