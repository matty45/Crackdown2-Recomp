package com.crackdown2.recomp;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;

import org.libsdl.app.SDLActivity;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Hosts the recompiled game through SDL3's activity. Game data lives in the
 * app's own external folder, which needs no storage permission:
 *   /sdcard/Android/data/com.crackdown2.recomp/files/assets  (extracted disc)
 *   /sdcard/Android/data/com.crackdown2.recomp/files/tu5     (extracted title update)
 * Settings, saves, caches and logs go to .../files/user and .../files/cache.
 */
public final class GameActivity extends SDLActivity {
  private static final String TAG = "Crackdown2";

  private File filesRoot() {
    File external = getExternalFilesDir(null);
    return external != null ? external : getFilesDir();
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    File root = filesRoot();
    File user = new File(root, "user");
    File cache = new File(root, "cache");
    user.mkdirs();
    cache.mkdirs();
    try {
      // The SDK's "executable folder" (crackdown2.toml, logs) on Android.
      Os.setenv("REX_APP_FOLDER", user.getAbsolutePath(), true);
    } catch (ErrnoException e) {
      Log.e(TAG, "setenv failed", e);
    }
    super.onCreate(savedInstanceState);
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    hideSystemBars();
  }

  @Override
  public void onWindowFocusChanged(boolean hasFocus) {
    super.onWindowFocusChanged(hasFocus);
    if (hasFocus) hideSystemBars();
  }

  private void hideSystemBars() {
    getWindow().getDecorView().setSystemUiVisibility(
        View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY | View.SYSTEM_UI_FLAG_FULLSCREEN
            | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
  }

  // SDL applies its own orientation (from the SDL_ORIENTATIONS hint, unset
  // here) when the window is created, which turned the phone to portrait and
  // gave the game a 1080x2410 swapchain. The game is landscape only.
  @Override
  public void setOrientationBis(int w, int h, boolean resizable, String hint) {
    setRequestedOrientation(android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE);
  }

  @Override
  protected String[] getLibraries() {
    // libmain.so pulls librexruntime.so in through DT_NEEDED; the GPU plugin is
    // dlopen'ed by soname from the same directory.
    return new String[] {"SDL3", "rexruntime", "main"};
  }

  @Override
  protected String[] getArguments() {
    File root = filesRoot();
    List<String> args = new ArrayList<>();
    args.add("--game_data_root=" + new File(root, "assets").getAbsolutePath());
    args.add("--update_data_root=" + new File(root, "tu5").getAbsolutePath());
    args.add("--user_data_root=" + new File(root, "user").getAbsolutePath());
    args.add("--cache_root=" + new File(root, "cache").getAbsolutePath());
    args.add("--gpu_plugin=xenos");
    args.add("--c2_gpu_backend=vulkan");
    args.add("--fullscreen=true");
    args.add("--log_file=" + new File(root, "user/crackdown2.log").getAbsolutePath());
    // Extra flags for testing: one per line in files/args.txt.
    File extra = new File(root, "args.txt");
    if (extra.isFile()) {
      try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(extra))) {
        String line;
        while ((line = r.readLine()) != null) {
          line = line.trim();
          if (!line.isEmpty() && !line.startsWith("#")) args.add(line);
        }
      } catch (java.io.IOException e) {
        Log.w(TAG, "args.txt unreadable", e);
      }
    }
    Log.i(TAG, "arguments: " + args);
    return args.toArray(new String[0]);
  }
}
