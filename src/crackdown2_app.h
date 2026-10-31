// crackdown2 - ReXGlue Recompiled Project
//
// Customize your app by overriding virtual hooks from rex::ReXApp.

#pragma once

#include <memory>

#include <rex/cvar.h>
#include <rex/input/mnk/mnk_input_driver.h>
#include <rex/rex_app.h>
#include <rex/ui/keybinds.h>
#include <rex/ui/window.h>

#include "game_console.h"
#include "graphics_menu.h"
#include "profiling.h"

void InstallQuietKernelStubs();
void InstallSerializedXInput();
void LoadRequestedGpuBackend(rex::RuntimeConfig& config);

class Crackdown2App : public rex::ReXApp {
 public:
  using rex::ReXApp::ReXApp;

  static std::unique_ptr<rex::ui::WindowedApp> Create(
      rex::ui::WindowedAppContext& ctx) {
    return std::unique_ptr<Crackdown2App>(new Crackdown2App(ctx, "crackdown2",
        PPCImageConfig));
  }

  // Swap the SDK's logging stubs for KeSave/RestoreFloatingPointState with
  // silent no-ops before the XEX import table is resolved (see hooks.cpp).
  void OnPreSetup(rex::RuntimeConfig& config) override {
    InstallQuietKernelStubs();
    InstallSerializedXInput();
    LoadRequestedGpuBackend(config);
    c2::ApplyAspectRatio();
    c2::StartProfilingIfRequested();
  }

  // Build our custom overlays and bind a key to toggle them. This runs after the
  // ImGuiDrawer exists, alongside the SDK's own overlays (debug F3, settings F4).
  void OnCreateDialogs(rex::ui::ImGuiDrawer* drawer) override {
    // The window exists by now, so give the main-menu EXIT row and the
    // APPLY & RESTART row (src/native_menu.cpp) a clean-shutdown action. Closing
    // the window on the UI thread runs its OnClosing path, which stops the
    // guest, audio and GPU threads; RequestDeferredQuit alone skips that and
    // leaves the process hanging.
    c2::SetQuitHandler([this] {
      app_context().CallInUIThreadDeferred([this] {
        if (window()) window()->RequestClose();
      });
    });

    // The GPU plugin's cvars exist by now; all three are hot-reloadable.
    c2::ApplyGameDefaults();

    graphics_menu_ = std::make_unique<GraphicsMenu>(drawer);
    rex::ui::RegisterBind("bind_graphics_menu", "F5", "Toggle the Graphics menu",
                          [this] { graphics_menu_->ToggleVisible(); });

    // The SDK's keyboard/mouse driver feeds the mouse to the right stick (and
    // hides/captures the cursor) only while "mouse look" is active. Make that
    // explicit whenever --mnk_mouse is set, and let F6 release the cursor again
    // for the ImGui overlays. Mouse delta is scaled per frame by
    // --mnk_sensitivity (default 1.0, which is very slow for a real mouse).
    if (rex::cvar::Query<bool>("mnk_mouse")) {
      rex::input::mnk::SetMouseLookActive(true);
    }
    rex::ui::RegisterBind("bind_mouse_look", "F6", "Toggle mouse look (right stick on the mouse)",
                          [] { rex::input::mnk::SetMouseLookActive(!rex::input::mnk::IsMouseLookActive()); });
    // Re-run the --c2_console_startup developer-console commands (e.g. a
    // TeleportPlayer that only makes sense once a save is loaded).
    rex::ui::RegisterBind("bind_console_startup", "F8", "Run the --c2_console_startup console commands",
                          [] { c2::RunStartupCommands(); });

    // Render-pass diagnostic toggles (cheat mode only). One key = one console
    // toggle, so there is no even/odd parity issue from the startup list running
    // twice. Used to isolate which pass costs the most in heavy zones.
    if (rex::cvar::Query<bool>("c2_cheats")) {
      rex::ui::RegisterBind("diag_shadows", "F7", "DIAG: toggle shadows",
                            [] { c2::QueueConsoleCommand("toggleshadows"); });
      rex::ui::RegisterBind("diag_alpha", "F9", "DIAG: toggle alpha pass",
                            [] { c2::QueueConsoleCommand("togglealphapass"); });
      rex::ui::RegisterBind("diag_lights", "F10", "DIAG: toggle global lights",
                            [] { c2::QueueConsoleCommand("togglegloballights"); });
      rex::ui::RegisterBind("diag_opaque", "F11", "DIAG: toggle opaque pass",
                            [] { c2::QueueConsoleCommand("toggleopaquepass"); });
      rex::ui::RegisterBind("diag_clutter", "F12", "DIAG: toggle clutter",
                            [] { c2::QueueConsoleCommand("toggleclutter"); });
    }
  }

  void OnShutdown() override {
    // Window close / Alt+F4 skips the menu's quit path; persist settings here too.
    c2::SaveSettings();
    rex::ui::UnregisterBind("bind_graphics_menu");
    rex::ui::UnregisterBind("bind_mouse_look");
    rex::ui::UnregisterBind("bind_console_startup");
    rex::ui::UnregisterBind("diag_shadows");
    rex::ui::UnregisterBind("diag_alpha");
    rex::ui::UnregisterBind("diag_lights");
    rex::ui::UnregisterBind("diag_opaque");
    rex::ui::UnregisterBind("diag_clutter");
  }

  // Override virtual hooks for customization:
  // void OnPostInitLogging() override {}
  // void OnLoadXexImage(std::string& xex_image) override {}
  // void OnPostSetup() override {}
  // void OnConfigurePaths(rex::PathConfig& paths) override {}

 private:
  std::unique_ptr<GraphicsMenu> graphics_menu_;
};
