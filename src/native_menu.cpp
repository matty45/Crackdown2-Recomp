// crackdown2 - native rows inside the game's own front-end option screens.
//
// Crackdown 2's front-end menus are built in C++ on top of a generic row
// framework (Scaleform GFx only renders the rows). Reverse-engineering notes
// live in docs/native_menu.md. The short version:
//
//   * A screen (component) owns menus; menu+44..+48 is the item pointer array.
//   * Menu_AddItem (sub_828F3260) allocates a 308-byte item: +36 kind, +40
//     action (component id to push for kind 2), +178/+179/+180 tooltip.
//   * Item_SetText (sub_828F3400, item, slot0, slot1) attaches a 652-byte text
//     object: +1 / +2 "has text" flags, +12 UTF-16BE wchar[64] slot 0 (the
//     centred value column), +140 wchar[64] slot 1 (the left-aligned label).
//     The stock rows pass their label as slot 1; the Controls screen keeps its
//     YES/NO in slot 0 and rewrites that on toggle, which is what we copy.
//   * Pressing A on a kind-3 row makes the framework call
//     screen->OnMenuEvent(0, menuIdx, rowIdx) through a bctrl at 0x828F1014.
//     We intercept that call site with a midasm hook and handle our own rows
//     there (the stock handlers ignore row indices they do not know).
//
// Everything goes on Options > Display (id 28, vtable 0x82164968, Init
// sub_828B5128), the one option screen with a proper scrolling list: first the
// graphics rows, then the mouse / keyboard / gamepad rows, then (only with
// --c2_cheats=true) the hidden cheat / debug rows, which drive the game's own
// developer console (game_console.h). The Controls screen (id 29) draws a fixed
// two-row box over the pad diagram and stops reacting to Back once extra rows
// are added, and the HUD screen (id 30) is not reachable from the front-end
// options list, so neither hosts rows.
//
// The rows render with the game's font, cursor, sounds and legend, scroll with
// the stock rows, and change real engine cvars or run console commands.

#include <cmath>
#include <cstdlib>
#include <rex/cvar.h>
#include <rex/hook.h>
#include <rex/ppc.h>
#include <rex/ppc/stack.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xmemory.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "game_console.h"

REXCVAR_DEFINE_BOOL(c2_cheats, false, "Game",
                    "Adds a hidden cheat/debug menu (god mode, weapons, skills, time of day, spawning, "
                    "teleport, perf graphs) at the bottom of Options > Display.");

// Recompiled guest routines. `__imp__name` is always the original body; the
// plain symbol is a weak alias that a definition here replaces.
extern "C" {
void __imp__sub_828B5128(PPCContext& ctx, uint8_t* base);  // FeDisplayOptions::Init
void __imp__sub_828AAAC8(PPCContext& ctx, uint8_t* base);  // FeMainMenu::Populate
void sub_828F3260(PPCContext& ctx, uint8_t* base);         // Menu_AddItem(menu) -> item
void sub_828F3400(PPCContext& ctx, uint8_t* base);         // Item_SetText(item, slot0, slot1)
}

namespace {

constexpr uint32_t kDisplayOptionsVtable = 0x82164968;
// FeMainMenu (the top-level MAIN GAME / DELUGE / ... screen). It adds its five
// stock rows in its Populate (sub_828AAAC8); we append an EXIT row after them.
constexpr uint32_t kMainMenuVtable = 0x821638C0;

// Menu object
constexpr uint32_t kMenuItemsBegin = 44;
constexpr uint32_t kMenuItemsEnd = 48;
// Item object
constexpr uint32_t kItemDirty = 10;
constexpr uint32_t kItemTextIndex = 12;
constexpr uint32_t kItemTexts = 24;
constexpr uint32_t kItemKind = 36;
constexpr uint32_t kItemAction = 40;
constexpr uint32_t kItemHasTip = 178;
constexpr uint32_t kItemTipEnabled = 179;
constexpr uint32_t kItemTip = 180;
constexpr uint32_t kItemKindNotifyOnly = 3;
// Text object
constexpr uint32_t kTextHasSlot0 = 1;
constexpr uint32_t kTextSlot0 = 12;
constexpr uint32_t kTextChars = 64;

template <typename T>
T ld(uint8_t* base, uint32_t addr) {
  return static_cast<T>(*rex::memory::GuestPtr<rex::be<T>*>(base, addr));
}
template <typename T>
void st(uint8_t* base, uint32_t addr, T value) {
  *rex::memory::GuestPtr<rex::be<T>*>(base, addr) = value;
}

uint8_t* guest_base() { return rex::system::kernel_state()->memory()->virtual_membase(); }

// Write an ASCII string as a NUL-terminated UTF-16BE wchar[max_chars] buffer.
void put_utf16(uint8_t* base, uint32_t dst, const std::string& s, size_t max_chars) {
  size_t n = std::min(s.size(), max_chars - 1);
  for (size_t i = 0; i < n; ++i) {
    st<uint16_t>(base, dst + uint32_t(i * 2), uint16_t(uint8_t(s[i])));
  }
  st<uint16_t>(base, dst + uint32_t(n * 2), 0);
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

struct Choice {
  const char* value;  // cvar value, or the console command argument
  const char* shown;  // text on the row
};

enum class RowKind {
  kCvar,          // A cycles a cvar through `choices`
  kCommandCycle,  // A runs `command` with the next choice substituted for %s
  kCommandOnce,   // A runs `command`; the row shows ACTIVATE / ON / OFF
  kQuit,          // A cleanly quits the game to the desktop
  kApplyRestart,  // A (twice, to confirm) saves settings and restarts the game
};

struct Row {
  const char* label;
  const char* tip;
  RowKind kind;
  const char* cvar;  // kCvar
  std::vector<Choice> choices;
  const char* mirror_cvar = nullptr;  // kCvar: second cvar kept in lockstep
  const char* command = nullptr;      // kCommandCycle / kCommandOnce
  bool toggle = false;                // kCommandOnce: the command toggles, show ON/OFF
  size_t state = 0;                   // kCommand*: current choice / toggle state
};

const Choice kOnOff[] = {{"false", "OFF"}, {"true", "ON"}};
const Choice kNone[] = {{"", ""}};

std::vector<Row> display_rows() {
  return {
      {"V-SYNC", "TOGGLE VERTICAL SYNC", RowKind::kCvar, "vsync", {kOnOff[0], kOnOff[1]}},
      {"FULLSCREEN", "SWITCH BETWEEN WINDOWED AND FULLSCREEN", RowKind::kCvar, "fullscreen",
       {kOnOff[0], kOnOff[1]}},
      {"FPS COUNTER", "SHOW THE FRAME RATE OVERLAY", RowKind::kCvar, "c2_fps_display",
       {kOnOff[0], kOnOff[1]}},
      {"ASPECT RATIO", "SHAPE OF THE RENDERED IMAGE: AUTO MATCHES YOUR MONITOR (NO BARS), A DIFFERENT SHAPE SHOWS "
       "BARS. WIDER = MORE FIELD OF VIEW, HUD STAYS IN THE CORNERS (TAKES EFFECT AFTER RESTART)", RowKind::kCvar,
       "c2_aspect_ratio",
       {{"auto", "AUTO"}, {"16:9", "16:9"}, {"16:10", "16:10"}, {"21:9", "21:9"}, {"32:9", "32:9"}}},
      {"RESOLUTION", "WINDOW HEIGHT WHEN NOT FULLSCREEN; THE WIDTH FOLLOWS THE ASPECT RATIO (TAKES EFFECT AFTER "
       "RESTART)", RowKind::kCvar, "resolution",
       {{"", "AUTO"}, {"1280x720", "720P"}, {"1920x1080", "1080P"}, {"2560x1440", "1440P"}, {"3840x2160", "4K"}}},
      {"RENDER SCALE", "INTERNAL RESOLUTION MULTIPLIER (TAKES EFFECT AFTER RESTART)", RowKind::kCvar,
       "draw_resolution_scale_x",
       {{"1", "1X"}, {"2", "2X"}, {"3", "3X"}, {"4", "4X"}},
       "draw_resolution_scale_y"},
      {"2X MSAA", "NATIVE 2X MSAA (TAKES EFFECT AFTER RESTART)", RowKind::kCvar, "native_2x_msaa",
       {kOnOff[0], kOnOff[1]}},
      {"ANTI-ALIASING", "POST-PROCESS AA ON THE FINAL IMAGE (TAKES EFFECT AFTER RESTART)", RowKind::kCvar,
       "swap_post_effect",
       {{"none", "OFF"}, {"fxaa", "FXAA"}, {"fxaa_extreme", "FXAA HIGH"}}},
      {"ANISOTROPIC FILTER", "TEXTURE FILTERING QUALITY", RowKind::kCvar, "anisotropic_override",
       {{"-1", "GAME"}, {"0", "OFF"}, {"2", "2X"}, {"3", "4X"}, {"4", "8X"}, {"5", "16X"}}},
      {"UPSCALING FILTER", "OUTPUT FILTER: BILINEAR, CAS SHARPEN OR FSR", RowKind::kCvar,
       "present_effect",
       {{"bilinear", "BILINEAR"}, {"cas", "CAS"}, {"fsr", "FSR"}, {"fsr2", "FSR 2"}, {"fsr3", "FSR 3"}}},
      {"GPU READBACK", "COPY GPU MEMEXPORT RESULTS BACK TO THE CPU. OFF IS 3-10X FASTER IN GAME", RowKind::kCvar,
       "readback_memexport", {kOnOff[0], kOnOff[1]}},
      {"GPU PAGE REFRESH", "RE-UPLOAD ALL CPU-WRITTEN GPU MEMORY EVERY FRAME. OFF IS ~12% FASTER IN GAME",
       RowKind::kCvar, "clear_memory_page_state", {kOnOff[0], kOnOff[1]}},
      {"PERFORMANCE MODE", "HIDE THE MOST DISTANT ENVIRONMENT DETAIL FOR A STEADY 30 FPS IN DENSE ZONES "
       "(FAR LANDMARKS LIKE THE AGENCY TOWER DISAPPEAR). TAKES EFFECT IMMEDIATELY.",
       RowKind::kCvar, "c2_performance_mode", {kOnOff[0], kOnOff[1]}},
      {"APPLY & RESTART", "SAVE THESE SETTINGS AND RESTART THE GAME (NEEDED FOR RESOLUTION / RENDER SCALE / "
       "MSAA / AA CHANGES). PRESS AGAIN TO CONFIRM.", RowKind::kApplyRestart, nullptr, {kNone[0]}},
  };
}

std::vector<Row> control_rows() {
  return {
      {"KEYBOARD AND MOUSE", "EMULATE A GAMEPAD WITH THE KEYBOARD AND MOUSE", RowKind::kCvar, "mnk_mode",
       {kOnOff[0], kOnOff[1]}},
      {"MOUSE LOOK", "MOUSE DRIVES THE RIGHT STICK (F6 ALSO TOGGLES)", RowKind::kCvar, "mnk_mouse",
       {kOnOff[0], kOnOff[1]}},
      {"MOUSE SENSITIVITY", "RIGHT STICK SPEED PER MOUSE MOVEMENT", RowKind::kCvar, "mnk_sensitivity",
       {{"0.5", "0.5"}, {"1", "1"}, {"1.5", "1.5"}, {"2", "2"}, {"3", "3"}, {"4", "4"}, {"6", "6"}, {"8", "8"}}},
      {"GAMEPAD DRIVER", "SDL (ANY PAD) OR XINPUT (TAKES EFFECT AFTER RESTART)", RowKind::kCvar,
       "input_backend",
       {{"sdl", "SDL"}, {"xinput", "XINPUT"}}},
      {"KEY BINDINGS", "PRESS F4 IN GAME TO REBIND KEYS, THEN SAVE TO CONFIG", RowKind::kCommandOnce, nullptr,
       {kNone[0]}, nullptr, ""},
  };
}

std::vector<Row> cheat_rows() {
  return {
      {"- CHEAT MENU -", "DEVELOPER CONSOLE SHORTCUTS (--c2_cheats). MOST ONLY WORK IN GAME", RowKind::kCommandOnce,
       nullptr, {kNone[0]}, nullptr, ""},
      {"GOD MODE", "PLAYER CANNOT BE DAMAGED", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr, "god", true},
      {"INFINITE AMMO", "NEVER RUN OUT OF AMMUNITION", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "infiniteammo", true},
      {"ALL WEAPONS", "GIVE THE AGENT ALL AVAILABLE EQUIPMENT", RowKind::kCommandOnce, nullptr, {kNone[0]},
       nullptr, "loaded"},
      {"MAX SKILLS", "SET EVERY AGENT SKILL TO MAXIMUM", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "maxagentskills"},
      {"SKILLS UP", "INCREMENT EVERY AGENT SKILL", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "incallskills"},
      {"FULL HEALTH", "RESTORE HEALTH", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr, "sethealth 100"},
      {"SUPPLY POINTS", "UNLOCK ALL AGENCY SUPPLY POINTS", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "unlock_supply_points"},
      {"ORBS", "TOGGLE AGILITY AND HIDDEN ORBS", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "toggleorbs", true},
      {"TIME OF DAY", "ADVANCE THE TIME OF DAY PHASE", RowKind::kCommandCycle, nullptr,
       {{"0.0", "0.00"}, {"0.25", "0.25"}, {"0.5", "0.50"}, {"0.75", "0.75"}}, nullptr, "todsetphase %s"},
      {"RAIN", "MAKE IT RAIN AROUND THE PLAYER", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr, "rain"},
      {"DIFFICULTY", "SET THE GAME DIFFICULTY", RowKind::kCommandCycle, nullptr,
       {{"normal", "NORMAL"}, {"tough", "TOUGH"}, {"ruthless", "RUTHLESS"}, {"psychotic", "PSYCHOTIC"},
        {"sadistic", "SADISTIC"}, {"veasy", "VERY EASY"}},
       nullptr, "SetGameDifficulty %s"},
      {"SPAWN ENEMY", "SUMMON A CELL PROTOTYPE NEXT TO THE PLAYER", RowKind::kCommandCycle, nullptr,
       {{"Cell_Male_Bad", "CELL MALE"}, {"Cell_Female_Bad", "CELL FEMALE"}, {"Cell_Armoured", "CELL ARMOURED"}},
       nullptr, "summon %s"},
      {"APOCALYPSE", "KILL ALL BOTS (PLAYER TAKES CREDIT)", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "apocalypse"},
      {"WARP TO AGENCY", "TELEPORT TO THE AGENCY TRAINING ROOM", RowKind::kCommandOnce, nullptr, {kNone[0]},
       nullptr, "TeleportPlayer 1842,27,-1782"},
      {"WARP UP", "TELEPORT 150M ABOVE THE AGENCY", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "TeleportPlayer 1842,180,-1782"},
      {"FLY CAM", "TOGGLE THE FREE FLY CAMERA", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr, "flycam",
       true},
      {"GAME FPS CAP", "GAME LOGIC TARGET FRAME RATE", RowKind::kCommandCycle, nullptr,
       {{"30", "30"}, {"60", "60"}, {"120", "120"}}, nullptr, "setfps %s"},
      {"PERF GRAPH", "SHOW THE GAME'S CPU/GPU PERFORMANCE GRAPHS", RowKind::kCommandOnce, nullptr, {kNone[0]},
       nullptr, "perfgraph", true},
      {"GPU TIMING", "SHOW THE GAME'S GPU TIMING OVERLAY", RowKind::kCommandOnce, nullptr, {kNone[0]}, nullptr,
       "gputiming", true},
      {"DLC LICENSE", "OVERRIDE ALL DLC LICENSES (TEST INSTALLED CONTENT)", RowKind::kCommandOnce, nullptr,
       {kNone[0]}, nullptr, "togglelicenseoverride", true},
  };
}

size_t current_choice(const Row& row) {
  if (row.kind != RowKind::kCvar) return row.state % std::max<size_t>(1, row.choices.size());
  if (!rex::cvar::GetFlagInfo(row.cvar)) return 0;
  std::string cur = rex::cvar::GetFlagByName(row.cvar);
  for (size_t i = 0; i < row.choices.size(); ++i) {
    if (cur == row.choices[i].value) return i;
  }
  // Numeric cvars print with trailing zeros ("3.000000"): compare as numbers.
  char* end = nullptr;
  double value = std::strtod(cur.c_str(), &end);
  if (end && end != cur.c_str() && *end == '\0') {
    for (size_t i = 0; i < row.choices.size(); ++i) {
      if (std::fabs(std::strtod(row.choices[i].value, nullptr) - value) < 1e-6) return i;
    }
  }
  // bool cvars may serialize as 0/1
  if (cur == "1" || cur == "0") return cur == "1" ? 1 : 0;
  return 0;
}

std::string row_value(const Row& row) {
  switch (row.kind) {
    case RowKind::kCvar:
    case RowKind::kCommandCycle:
      return row.choices.empty() ? "" : row.choices[current_choice(row)].shown;
    case RowKind::kCommandOnce:
      if (!row.command || !*row.command) return "";
      return row.toggle ? (row.state ? "ON" : "OFF") : "ACTIVATE";
    case RowKind::kQuit:
      return "";
    case RowKind::kApplyRestart:
      return row.state ? "CONFIRM?" : "APPLY";
  }
  return "";
}

struct AddedRow {
  uint32_t item;
  size_t row;
};

struct Screen {
  uint32_t vtable;
  std::vector<Row> rows;
  // Display-option items keep their label in text slot 1 (the left column) and a
  // value in slot 0. The main menu's own rows instead put their label in slot 0,
  // so our appended rows there must match or they render in the wrong column.
  bool label_slot0 = false;
  uint32_t screen = 0;     // screen object carrying our rows
  uint32_t first_row = 0;  // index of our first row in its menu
  std::vector<AddedRow> items;
};

// The single EXIT row appended to the top-level main menu.
std::vector<Row> mainmenu_rows() {
  return {
      {"EXIT", "QUIT CRACKDOWN 2 TO THE DESKTOP", RowKind::kQuit, nullptr, {kNone[0]}},
  };
}

Screen g_display{kDisplayOptionsVtable, display_rows()};
Screen g_controls{kDisplayOptionsVtable, control_rows()};
Screen g_hud{kDisplayOptionsVtable, cheat_rows()};
Screen g_mainmenu{kMainMenuVtable, mainmenu_rows(), true};
Screen* const g_screens[] = {&g_display, &g_controls, &g_hud, &g_mainmenu};

// Append `scr.rows` to the first menu of `screen` (call after the stock Init).
void append_rows(PPCContext& ctx, uint8_t* base, uint32_t screen, Screen& scr) {
  uint32_t menus = ld<uint32_t>(base, screen + 48);
  uint32_t menu = menus ? ld<uint32_t>(base, menus) : 0;
  if (!menu) return;

  scr.screen = screen;
  scr.items.clear();
  scr.first_row = (ld<uint32_t>(base, menu + kMenuItemsEnd) - ld<uint32_t>(base, menu + kMenuItemsBegin)) / 4;

  for (Row& row : scr.rows) {
    // Re-entering the screen disarms the APPLY & RESTART confirmation.
    if (row.kind == RowKind::kApplyRestart) row.state = 0;
    if (row.kind == RowKind::kCvar) {
      const rex::cvar::FlagEntry* info = rex::cvar::GetFlagInfo(row.cvar);
      if (!info) continue;
      // Keep only the values this runtime build accepts (e.g. present_effect
      // is bilinear-only when the SDK was built without FidelityFX), and drop
      // rows that would have nothing to cycle through.
      if (info->constraints.HasAllowedValues()) {
        const auto& allowed = info->constraints.allowed_values;
        std::vector<Choice> kept;
        for (const Choice& c : row.choices) {
          if (std::find(allowed.begin(), allowed.end(), c.value) != allowed.end()) kept.push_back(c);
        }
        row.choices = std::move(kept);
      }
      if (row.choices.size() < 2) continue;
    }

    ctx.r3.u32 = menu;
    sub_828F3260(ctx, base);
    const uint32_t item = ctx.r3.u32;
    if (!item) break;

    std::vector<uint8_t> value = encode_utf16(row_value(row));
    std::vector<uint8_t> label = encode_utf16(row.label);
    uint32_t guest_value = rex::ppc::stack_push(ctx, base, value.data(), uint32_t(value.size()));
    uint32_t guest_label = rex::ppc::stack_push(ctx, base, label.data(), uint32_t(label.size()));
    ctx.r3.u32 = item;
    // Display rows: value in slot 0 (centre), label in slot 1 (left column, what
    // HUD OPACITY / GAMMA use). Main-menu rows keep the label in slot 0 to line up
    // with the stock MAIN GAME / OPTIONS entries.
    ctx.r4.u32 = scr.label_slot0 ? guest_label : guest_value;  // slot 0
    ctx.r5.u32 = scr.label_slot0 ? guest_value : guest_label;  // slot 1
    sub_828F3400(ctx, base);
    // Each push is aligned on its own, so pop them one at a time in reverse.
    rex::ppc::stack_pop(ctx, uint32_t(label.size()));
    rex::ppc::stack_pop(ctx, uint32_t(value.size()));

    base[item + kItemHasTip] = 1;
    base[item + kItemTipEnabled] = 1;
    put_utf16(base, item + kItemTip, row.tip, kTextChars);
    st<uint32_t>(base, item + kItemKind, kItemKindNotifyOnly);
    st<int32_t>(base, item + kItemAction, -1);
    scr.items.push_back({item, size_t(&row - scr.rows.data())});
  }
}

void refresh_row_text(uint8_t* base, uint32_t item, const Row& row) {
  const uint32_t texts = ld<uint32_t>(base, item + kItemTexts);
  const uint32_t text_index = ld<uint32_t>(base, item + kItemTextIndex);
  const uint32_t text_obj = texts ? ld<uint32_t>(base, texts + text_index * 4) : 0;
  if (!text_obj) return;
  put_utf16(base, text_obj + kTextSlot0, row_value(row), kTextChars);
  base[text_obj + kTextHasSlot0] = 1;
  base[item + kItemDirty] = 1;
}

std::string substitute(const char* command, const char* arg) {
  std::string s = command ? command : "";
  size_t p = s.find("%s");
  if (p != std::string::npos) s.replace(p, 2, arg ? arg : "");
  return s;
}

void activate(Row& row) {
  switch (row.kind) {
    case RowKind::kCvar: {
      const size_t next = (current_choice(row) + 1) % row.choices.size();
      rex::cvar::SetFlagByName(row.cvar, row.choices[next].value);
      if (row.mirror_cvar && rex::cvar::GetFlagInfo(row.mirror_cvar)) {
        rex::cvar::SetFlagByName(row.mirror_cvar, row.choices[next].value);
      }
      break;
    }
    case RowKind::kCommandCycle:
      row.state = (row.state + 1) % row.choices.size();
      c2::QueueConsoleCommand(substitute(row.command, row.choices[row.state].value));
      break;
    case RowKind::kCommandOnce:
      if (row.command && *row.command) {
        c2::QueueConsoleCommand(row.command);
        if (row.toggle) row.state ^= 1;
      }
      break;
    case RowKind::kQuit:
      c2::RequestQuit();
      break;
    case RowKind::kApplyRestart:
      // First press arms the confirmation (row shows CONFIRM?); second press
      // saves the settings and restarts. Re-entering the screen re-disarms it.
      if (row.state == 0) {
        row.state = 1;
      } else {
        row.state = 0;
        c2::RequestRestart();
      }
      break;
  }
}

}  // namespace

// Replaces the screens' Init: run the original (loads the movie, creates the
// menu, adds the stock rows), then append ours.
extern "C" void sub_828B5128(PPCContext& ctx, uint8_t* base) {  // FeDisplayOptions::Init
  const uint32_t screen = ctx.r3.u32;
  __imp__sub_828B5128(ctx, base);
  append_rows(ctx, base, screen, g_display);
  append_rows(ctx, base, screen, g_controls);
  if (REXCVAR_GET(c2_cheats)) append_rows(ctx, base, screen, g_hud);
}

// Replaces FeMainMenu::Populate: run the original (adds MAIN GAME / DELUGE /
// KEYS TO THE CITY / MULTIPLAYER / OPTIONS), then append our EXIT row.
extern "C" void sub_828AAAC8(PPCContext& ctx, uint8_t* base) {  // FeMainMenu::Populate
  const uint32_t screen = ctx.r3.u32;
  __imp__sub_828AAAC8(ctx, base);
  append_rows(ctx, base, screen, g_mainmenu);
}

// Midasm hook just before the framework's screen->OnMenuEvent(0, menu, row)
// call for an activated row (default_hooks.toml, 0x828F1014). r3 = screen,
// r6 = selected row index, r26 = menu object.
void C2MenuItemActivated(PPCRegister& r3, PPCRegister& r5, PPCRegister& r6, PPCRegister& r26) {
  (void)r5;
  uint8_t* base = guest_base();
  const uint32_t screen = r3.u32;
  if (!screen) return;
  const uint32_t vtable = ld<uint32_t>(base, screen);

  for (Screen* scr : g_screens) {
    if (screen != scr->screen || vtable != scr->vtable) continue;

    const int32_t selected = int32_t(r6.u32);
    const int32_t index = selected - int32_t(scr->first_row);
    if (index < 0 || size_t(index) >= scr->items.size()) continue;  // another block on this menu

    const uint32_t menu = r26.u32;
    const uint32_t item = ld<uint32_t>(base, ld<uint32_t>(base, menu + kMenuItemsBegin) + uint32_t(selected) * 4);
    if (item != scr->items[size_t(index)].item) continue;

    Row& row = scr->rows[scr->items[size_t(index)].row];
    activate(row);
    refresh_row_text(base, item, row);
    return;
  }
}
