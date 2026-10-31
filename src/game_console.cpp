#include "game_console.h"

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/ppc/stack.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xmemory.h>

#include <algorithm>
#include <deque>
#include <filesystem>
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

REXCVAR_DEFINE_STRING(c2_console_startup, "", "Game",
                      "Developer console commands to run once a few seconds after boot, separated by ';' "
                      "(for example \"perfgraph;gputiming\"). See docs/console_commands.md.");

extern "C" {
void sub_825CE628(PPCContext& ctx, uint8_t* base);        // Console_Execute(console, wchar_t* line, context)
void __imp__RWS_MainLoop_Poll(PPCContext& ctx, uint8_t* base);
}

namespace {

// Core globals live at 0x83800000; +2804 holds the console object pointer
// (Core_Init executes its "minp press ..." input-map commands through it).
constexpr uint32_t kConsoleObjectPtr = 0x83800000 + 2804;
// Local player object (Core globals + 3976). The game's own console callers
// pass `player + 1352` as the command context; player commands (TeleportPlayer,
// god, loaded, ...) check it and silently do nothing when it is 0.
constexpr uint32_t kLocalPlayerPtr = 0x83800000 + 3976;
constexpr uint32_t kPlayerContextOffset = 1352;
REXCVAR_DEFINE_INT32(c2_console_startup_delay, 4, "Game",
                     "Seconds after boot before --c2_console_startup runs (the front end is up after ~4; "
                     "a loaded save needs 60+). F8 runs the same commands again at any time.");
REXCVAR_DEFINE_BOOL(c2_performance_mode, false, "Game",
                    "Performance mode: hide the most distant environment detail (the game's own "
                    "togglelod4env) so dense city zones hold a steady 30 fps on slower CPUs. Far-away "
                    "landmarks such as the Agency tower disappear until you get closer. Can be toggled "
                    "live from Options > Display or the F5 overlay.");
bool g_performance_mode_applied = false;
// Values ApplyGameDefaults put in place, as the cvars print them, so that
// SaveSettings does not persist them as if the user had chosen them (which
// would freeze them in crackdown2.toml and block any later default change).
std::map<std::string, std::string> g_game_default_values;
REXCVAR_DEFINE_STRING(c2_aspect_ratio, "auto", "Game",
                      "Aspect ratio the game renders at: auto (match the primary monitor), 16:9, "
                      "16:10, 21:9, 32:9 or any W:H. The guest video mode is derived from it, so "
                      "the engine widens the field of view and keeps the HUD in the corners; a "
                      "monitor of a different shape shows bars. Takes effect after restart.")
    .lifecycle(rex::cvar::Lifecycle::kRequiresRestart);

double MonitorAspect() {
#if defined(_WIN32)
  int w = GetSystemMetrics(SM_CXSCREEN);
  int h = GetSystemMetrics(SM_CYSCREEN);
  if (w > 0 && h > 0) return double(w) / double(h);
#endif
  return 16.0 / 9.0;
}

double ParseAspect(const std::string& s, double fallback) {
  unsigned a = 0, b = 0;
  if (std::sscanf(s.c_str(), "%u:%u", &a, &b) == 2 && a && b) return double(a) / double(b);
  return fallback;
}

// The RESOLUTION preset ("WxH", "1080p", "4k" or "" for auto) as a height.
int PresetHeight(const std::string& s) {
  unsigned w = 0, h = 0;
  if (std::sscanf(s.c_str(), "%ux%u", &w, &h) == 2) return int(h);
  if (s == "4k" || s == "4K") return 2160;
  if (std::sscanf(s.c_str(), "%up", &h) == 1) return int(h);
  return 0;
}

std::mutex g_mutex;
std::deque<std::string> g_queue;

// TOML basic-string quoting (backslashes in Windows paths must be escaped).
std::string TomlQuote(const std::string& s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04X", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + "\"";
}
uint32_t g_ticks = 0;
bool g_startup_done = false;
std::mutex g_quit_mutex;
std::function<void()> g_quit_handler;

template <typename T>
T ld(uint8_t* base, uint32_t addr) {
  return static_cast<T>(*rex::memory::GuestPtr<rex::be<T>*>(base, addr));
}

std::vector<uint8_t> encode_utf16(const std::string& s) {
  std::vector<uint8_t> out;
  out.reserve(s.size() * 2 + 2);
  for (unsigned char c : s) {
    out.push_back(0);
    out.push_back(c);
  }
  out.push_back(0);
  out.push_back(0);
  return out;
}

}  // namespace

namespace c2 {

bool ConsoleReady() {
  uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
  return ld<uint32_t>(base, kConsoleObjectPtr) != 0;
}

bool ExecConsoleCommand(PPCContext& ctx, uint8_t* base, const std::string& command) {
  const uint32_t console = ld<uint32_t>(base, kConsoleObjectPtr);
  if (!console || command.empty()) {
    REXLOG_WARN("console: cannot run '{}' (console object {:#x})", command, console);
    return false;
  }
  REXLOG_INFO("console: executing '{}'", command);

  // The caller's volatile registers are live (we run after the original
  // function returned, before its caller resumes), so keep a copy.
  PPCContext saved = ctx;
  std::vector<uint8_t> line = encode_utf16(command);
  const uint32_t guest_line = rex::ppc::stack_push(ctx, base, line.data(), uint32_t(line.size()));
  ctx.r3.u32 = console;
  ctx.r4.u32 = guest_line;
  const uint32_t player = ld<uint32_t>(base, kLocalPlayerPtr);
  ctx.r5.u32 = player ? player + kPlayerContextOffset : 0;
  sub_825CE628(ctx, base);
  rex::ppc::stack_pop(ctx, uint32_t(line.size()));
  ctx = saved;
  REXLOG_INFO("console: {}", command);
  return true;
}

void RunStartupCommands() {
  std::string startup = REXCVAR_GET(c2_console_startup);
  std::stringstream ss(startup);
  std::string cmd;
  while (std::getline(ss, cmd, ';')) {
    if (!cmd.empty()) QueueConsoleCommand(cmd);
  }
}

void QueueConsoleCommand(const std::string& command) {
  if (command.empty()) return;
  std::lock_guard<std::mutex> lock(g_mutex);
  g_queue.push_back(command);
}

void SetQuitHandler(std::function<void()> handler) {
  std::lock_guard<std::mutex> lock(g_quit_mutex);
  g_quit_handler = std::move(handler);
}

void RequestQuit() {
  // Keep menu / F5 changes across a plain quit too, not only APPLY & RESTART.
  SaveSettings();
  std::function<void()> handler;
  {
    std::lock_guard<std::mutex> lock(g_quit_mutex);
    handler = g_quit_handler;
  }
  if (handler) {
    REXLOG_INFO("console: quit requested from menu; closing window.");
    handler();
  } else {
    REXLOG_WARN("console: quit requested but no quit handler installed.");
  }
}

void SaveSettings() {
#if defined(_WIN32)
  wchar_t exe[MAX_PATH];
  DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    REXLOG_ERROR("settings: GetModuleFileName failed; settings not saved.");
    return;
  }
  std::filesystem::path config = std::filesystem::path(exe).parent_path() / "crackdown2.toml";

  // Not rex::cvar::SaveConfig: it writes string values verbatim, so a Windows
  // path such as log_file = "C:\cd2\x.log" produces invalid TOML that the SDK's
  // parser rejects on the next start - silently (logging is not up yet), and
  // nothing from the file loads. Write the file here instead, and only with the
  // values the user changed (menus, F5 overlay, console) or that came from this
  // file, never the launcher's command-line flags.
  std::string out =
      "# Crackdown 2 settings, written when the game exits. Command-line flags override these.\n";
  size_t count = 0;
  for (const rex::cvar::FlagEntry& e : rex::cvar::GetRegistry()) {
    if (e.type == rex::cvar::FlagType::Command || !e.getter) continue;
    if (e.source != rex::cvar::Source::kRuntime && e.source != rex::cvar::Source::kConfig) continue;
    std::string value = e.getter();
    if (value == e.default_value) continue;
    auto game_default = g_game_default_values.find(e.name);
    if (game_default != g_game_default_values.end() && game_default->second == value) continue;
    out += e.name + " = " + (e.type == rex::cvar::FlagType::String ? TomlQuote(value) : value) + "\n";
    ++count;
  }
  std::ofstream file(config, std::ios::binary | std::ios::trunc);
  if (!file) {
    REXLOG_ERROR("settings: cannot write {}", config.string());
    return;
  }
  file << out;
  REXLOG_INFO("settings: saved {} value(s) to {}", count, config.string());
#endif
}

void ApplyAspectRatio() {
  const std::string setting = REXCVAR_GET(c2_aspect_ratio);
  double aspect = std::clamp(ParseAspect(setting, MonitorAspect()), 1.0, 4.0);
  // Guest video mode: keep the 720 lines the game expects, widen to the aspect
  // (multiple of 8). The game reads this through XGetVideoMode and uses it for
  // its projection and HUD layout.
  const int vm_h = 720;
  const int vm_w = std::clamp(int(std::lround(vm_h * aspect / 8.0)) * 8, 640, 4095);
  // Window size: the RESOLUTION preset gives the height, the width follows the
  // aspect; without a preset the video mode size is used. Fullscreen ignores it.
  int win_h = PresetHeight(rex::cvar::GetFlagByName("resolution"));
  if (win_h < 480) win_h = vm_h;
  const int win_w = std::clamp(int(std::lround(win_h * aspect)), 640, 8192);
  rex::cvar::SetFlagByName("video_mode_width", std::to_string(vm_w));
  rex::cvar::SetFlagByName("video_mode_height", std::to_string(vm_h));
  rex::cvar::SetFlagByName("window_width", std::to_string(win_w));
  rex::cvar::SetFlagByName("window_height", std::to_string(win_h));
  // These are set on every start, so nothing is "pending a restart" because of
  // them (or because of the values crackdown2.toml just loaded).
  rex::cvar::ClearPendingRestartFlags();
  REXLOG_INFO("display: aspect {} ({:.3f}) -> video mode {}x{}, window {}x{}", setting, aspect,
              vm_w, vm_h, win_w, win_h);
}

void ApplyGameDefaults() {
  // This game's faster defaults (README "Performance"). Anything the user set
  // on the command line, in crackdown2.toml or from a menu outranks them.
  static const char* const kDefaults[][2] = {
      {"readback_memexport", "false"},
      {"clear_memory_page_state", "false"},
      // Picture defaults: v-sync and fullscreen stay at the SDK defaults (on),
      // aspect ratio auto, 2x MSAA on, post AA off, 16x anisotropic filtering.
      {"native_2x_msaa", "true"},
      {"anisotropic_override", "5"},
      // Keyboard/mouse: the SDK scales mouse movement by mnk_sensitivity * 200
      // per poll, so 1.0 barely moves the camera; shoot and lock-on on the mouse.
      {"mnk_sensitivity", "3.0"},
      // Keyboard layout on the game's own pad roles: WASD move (SDK default),
      // Space jump (A), E melee / hold to pick up objects (B), Q enter or exit
      // vehicle and use lifts (Y), Shift crouch (left stick click), F pick up
      // weapon (X), R reload (LB), G grenade (RB), mouse buttons fire (RT) and
      // lock on (LT), middle button zoom (right stick click).
      {"keybind_a", "Space"},
      {"keybind_b", "E"},
      {"keybind_y", "Q"},
      {"keybind_x", "F"},
      {"keybind_lstick_press", "Shift"},
      {"keybind_rstick_press", "K,MMB"},
      {"keybind_left_shoulder", "R"},
      {"keybind_right_shoulder", "G"},
      {"keybind_right_trigger", "LMB"},
      {"keybind_left_trigger", "RMB"},
  };
  for (const auto& d : kDefaults) {
    const rex::cvar::FlagEntry* info = rex::cvar::GetFlagInfo(d[0]);
    if (!info) {
      REXLOG_WARN("settings: cvar {} is not registered; game default not applied", d[0]);
      continue;
    }
    if (info->source != rex::cvar::Source::kDefault) continue;
    if (rex::cvar::SetFlagByName(d[0], d[1])) {
      g_game_default_values[d[0]] = rex::cvar::GetFlagByName(d[0]);
    }
  }
}

void RequestRestart() {
#if defined(_WIN32)
  wchar_t exe[MAX_PATH];
  DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    REXLOG_ERROR("restart: GetModuleFileName failed; quitting instead.");
    RequestQuit();
    return;
  }
  std::filesystem::path exe_path(exe);

  // Persist the changed cvars (resolution, render scale, ...) so the relaunched
  // instance loads them from <exe>/crackdown2.toml at startup.
  SaveSettings();

  // Relaunch only after this process has fully exited, so the exclusively-locked
  // shader/pipeline cache is released first. A tiny cmd stub polls for our PID to
  // disappear, then re-runs us with the exact same command line.
  //
  // If we were started inside a kill-on-job-close job object (e.g. from a
  // scheduled task), a detached child is killed when the job is torn down as we
  // exit, so the relaunch never happens - and such jobs usually forbid
  // CREATE_BREAKAWAY_FROM_JOB too. In that case, hand the relaunch to the Task
  // Scheduler service instead: it runs the stub outside our job. Otherwise (the
  // common double-click / launcher-script case) spawn the stub directly, which is
  // self-contained and leaves no task behind.
  const DWORD pid = GetCurrentProcessId();
  const std::wstring game_cmd = GetCommandLineW();
  constexpr wchar_t kTaskName[] = L"cd2_apply_restart";

  BOOL in_job = FALSE;
  IsProcessInJob(GetCurrentProcess(), nullptr, &in_job);
  bool via_task = in_job != FALSE;

  wchar_t tmp[MAX_PATH];
  if (GetTempPathW(MAX_PATH, tmp) == 0) {
    REXLOG_ERROR("restart: GetTempPath failed; quitting instead.");
    RequestQuit();
    return;
  }
  std::filesystem::path stub = std::filesystem::path(tmp) / "crackdown2_restart.cmd";
  std::filesystem::path vbs = std::filesystem::path(tmp) / "crackdown2_restart.vbs";
  {
    std::wofstream f(stub);
    f << L"@echo off\r\n";
    f << L":w\r\n";
    f << L"tasklist /fi \"PID eq " << pid << L"\" 2>nul | find \"" << pid
      << L"\" >nul && (ping -n 2 127.0.0.1 >nul & goto w)\r\n";
    if (via_task) {
      // Run the game synchronously (no `start`) so the hosting task stays alive
      // (and its job open) for as long as the game runs, then clean up on exit.
      f << game_cmd << L"\r\n";
      f << L"schtasks /delete /tn " << kTaskName << L" /f >nul 2>&1\r\n";
      f << L"del \"" << vbs.wstring() << L"\"\r\n";
    } else {
      f << L"start \"\" " << game_cmd << L"\r\n";
    }
    f << L"del \"%~f0\"\r\n";
  }
  if (via_task) {
    // The task runs this .vbs via wscript (a windowless host), which runs the cmd
    // stub with a hidden window and waits for it - so no console flashes on screen
    // while the game is restarting or running. ("" doubles to one quote in VBScript.)
    std::wofstream v(vbs);
    v << L"CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" << stub.wstring()
      << L"\"\"\", 0, True\r\n";
  }

  auto run_sync = [](const std::wstring& command) -> bool {
    std::vector<wchar_t> buf(command.begin(), command.end());
    buf.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
      return false;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
  };

  auto spawn_direct = [&]() -> bool {
    std::wstring cmdline = L"cmd.exe /c \"" + stub.wstring() + L"\"";
    const DWORD base_flags = CREATE_NO_WINDOW | DETACHED_PROCESS;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    auto try_flags = [&](DWORD flags) -> bool {
      std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
      buf.push_back(L'\0');
      if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, flags, nullptr,
                          exe_path.parent_path().wstring().c_str(), &si, &pi)) {
        return false;
      }
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return true;
    };
    return try_flags(base_flags | CREATE_BREAKAWAY_FROM_JOB) || try_flags(base_flags);
  };

  auto spawn_via_task = [&]() -> bool {
    // A one-shot task whose action runs the stub; /run triggers it now and the
    // Task Scheduler service hosts it outside our job. /st is a dummy time.
    std::wstring create = std::wstring(L"schtasks /create /f /tn ") + kTaskName +
                          L" /sc once /st 23:59 /tr \"wscript \\\"" + vbs.wstring() + L"\\\"\"";
    std::wstring run = std::wstring(L"schtasks /run /tn ") + kTaskName;
    return run_sync(create) && run_sync(run);
  };

  bool launched = via_task ? (spawn_via_task() || spawn_direct())
                           : (spawn_direct() || spawn_via_task());
  if (launched) {
    REXLOG_INFO("restart: relaunch scheduled ({}); quitting to apply settings.",
                via_task ? "task" : "direct");
  } else {
    REXLOG_ERROR("restart: could not start relaunch ({}); quitting without relaunch.",
                 static_cast<unsigned long>(GetLastError()));
  }
#else
  REXLOG_WARN("restart: self-restart is only implemented on Windows; quitting.");
#endif
  RequestQuit();
}

}  // namespace c2

// RWS_MainLoop_Poll runs once per frame on the game thread (it also drives
// UI_Update, so menu actions and console commands share a thread): drain the queue
// there so commands from the UI thread execute with a proper guest context.
extern "C" void RWS_MainLoop_Poll(PPCContext& ctx, uint8_t* base) {
  __imp__RWS_MainLoop_Poll(ctx, base);

  if (g_ticks == 0) REXLOG_INFO("console: main loop poll running (console {})", c2::ConsoleReady() ? "ready" : "not ready");
  if (!g_startup_done && ++g_ticks >= uint32_t(std::max(1, REXCVAR_GET(c2_console_startup_delay))) * 60u) {
    g_startup_done = true;
    c2::RunStartupCommands();
  }
  // Keep the game's LOD4 environment toggle in step with c2_performance_mode
  // (Display menu, F5 overlay or crackdown2.toml). togglelod4env is a toggle
  // with no query, so remember what we applied; the engine starts with it off.
  if (g_startup_done && c2::ConsoleReady() &&
      REXCVAR_GET(c2_performance_mode) != g_performance_mode_applied) {
    g_performance_mode_applied = !g_performance_mode_applied;
    c2::QueueConsoleCommand("togglelod4env");
  }

  std::deque<std::string> pending;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    pending.swap(g_queue);
  }
  for (const std::string& cmd : pending) {
    c2::ExecConsoleCommand(ctx, base, cmd);
  }
}
