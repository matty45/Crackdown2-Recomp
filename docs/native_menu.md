# Crackdown 2 front-end menu internals (reverse-engineering notes)

These notes back `src/native_menu.cpp`, which adds PC graphics rows to the
game's own Display Options screen. Addresses are for the TU5 (default.xexp)
image; `sub_XXXXXXXX` names match the recompiled code in `generated/`.

## Assets

* `UI/*.pack` + `.pack.toc`: `PACK` archives. The TOC is big-endian: header
  (`PACK`, version 2, 0, entry count at +12, 0x800 alignment), then 16-byte
  entries `{name offset (UTF-16 code units), data offset, size, 0xDEDEDEDE}`
  from +0x20, then a UTF-16BE string table. Entries are Scaleform `CFX`
  movies (zlib-compressed SWF, `CFX` + uncompressed length + zlib stream) and
  DDS textures. `tools/ui_pack_extract.py` extracts
  them and rewrites CFX as plain `FWS` SWF.
* The menu movies carry no ActionScript: `UI\FeMenu.gfx` / `UI\OptionsScreen.gfx`
  only hold the row art and five text fields per menu (`item0..item4`,
  `itemTip0..`). All menu logic is C++.
* Labels come from `Local/<lang>/Text/GameStrings.str` (`2BSL`): a sorted
  big-endian `(hash, offset)` index followed by UTF-16BE strings (offsets in
  code units). TU additions live in `TUText/TitleUpdateStrings.str`.
  `tools/gamestrings_resolve.py` resolves a hash to text; `tools/swf_strings.py` lists a movie's exports and ActionScript strings. Lookup in the game is
  `GetStringTable()` = `sub_8264E5A8`, `GetString(table, hash)` = `sub_8264E728`.

## Components (screens)

`eComponentID_*` strings are stored in **reverse** enum order. Useful values:

| id | component | id | component |
|----|-----------|----|-----------|
| 12 | FeMainMenu | 24 | FeGamma |
| 14 | FeCampaignRoot | 27 | FeAudioOptions |
| 23 | FeOptions | 28 | FeDisplayOptions |
| 29 | FeControlOptions | 30 | FeHudOptions |
| 34 | FeDelugeRoot | | |

The component factory `sub_82892210` builds the object for an id and installs
its vtable. Vtables share one layout (slot = index into the pointer table):

| slot | FeMainMenu (vt 0x821638C0) | FeDisplayOptions (vt 0x82164968) | meaning |
|------|----------------------------|----------------------------------|---------|
| 3 | `sub_828AAA08` | `sub_828B5128` | Init: load movies, create menu, add rows |
| 6 | `sub_828AAAC8` | nop | Populate (main menu adds its 5 rows here) |
| 7 | `sub_828AAE38` | `sub_828B52D0` | OnShow: header text, A/B legend |
| 15 | `sub_828AB118` | `sub_827E56A8` (no-op) | OnMenuEvent(type, a, b) |

## Menu framework

* `LoadMovie(screen, path, slot=24, 0, 0)` = `sub_828F2898`.
* `CreateMenu(screen, style, visibleRows=5, 0)` = `sub_828F3040`, 844-byte
  object stored in the screen's menu array (`screen+48`). `menu+44/+48` item
  pointer array begin/end, `menu+24` selected row, `menu+56` row style,
  `menu+73` / `+137` GFx instance-name prefixes (`item`, `itemTip`).
  Menus scroll: Audio has 10 rows in 5 slots.
* `Menu_AddItem(menu)` = `sub_828F3260` → 308-byte item, index at `+4`,
  defaults kind `+36 = 3`, action `+40 = -1`.
* `Item_SetText(item, slot0, slot1)` = `sub_828F3400` → appends a 652-byte
  text object (`+1` / `+2` slot present flags, `+12` UTF-16BE wchar[64] slot 0,
  `+140` wchar[64] slot 1). Slot 1 is the left-aligned label column (HUD
  OPACITY / GAMMA pass `slot0 = 0, slot1 = label`); slot 0 is the centred,
  narrow value column (word-wrapped, so keep it short). The Controls screen
  writes YES/NO into slot 0 and rewrites `+12` on toggle with `+1 = 1`.
  A row with several text objects is a value list: left/right cycles
  `item+12` and the framework calls `OnMenuEvent(2, newValue, itemId)`
  (bctrl at `0x828F17F4`).
* Tooltip: `item+178` has-tip, `+179` enabled, `+180` UTF-16BE wchar[64]
  (shown as the orange subtitle while the row is highlighted).
* Input handler `sub_828F0CE8`. On A, `switch(item+36)`:
  * kind 2: queue a component push of `item+40` (screen `+36` = id, `+4` = 7)
    and call `OnMenuEvent(0, menuIdx, selectedRow)` (bctrl at `0x828F1014`).
  * kind 1 / 3: only the `OnMenuEvent(0, ...)` call. Controls options uses
    this: its handler flips the setting and rewrites the row's slot-0 text
    with YES/NO (`sub_828B4CC0`).
  * kind 4 / 5: show prompt `1 << action` (DLC purchase dialog etc.).
* Main menu rows (`sub_828AAAC8`): MAIN GAME→14, DELUGE→34 or the purchase
  prompt, KEYS TO THE CITY, MULTIPLAYER, OPTIONS→23.
* Options root (`sub_828B66D8`): AUDIO→27, DISPLAY→28, CONTROLS→29, CREDITS.
* Display Options (`sub_828B5128`): HUD OPACITY→30, GAMMA→24.

## How the native rows work

`src/native_menu.cpp` replaces `sub_828B5128` (the recompiled symbol is a weak
alias; `__imp__sub_828B5128` is the original). It runs the original, then
calls the game's own `Menu_AddItem` / `Item_SetText` to append kind-3 rows
with the label in slot 1 and the current value in slot 0. A midasm hook at `0x828F1014` sees the
`OnMenuEvent(0, …)` call for the Display Options screen, cycles the row's
cvar with `rex::cvar::SetFlagByName`, rewrites the text object and marks it
dirty. No assets are modified.
