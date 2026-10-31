#!/usr/bin/env bash
# Builds the Android (arm64-v8a) APK: rexglue SDK + game as shared libraries
# with the NDK, then the Gradle wrapper packs them with SDL3's activity.
#
#   tools/build_android.sh [configure|native|apk|install|all]   (default: all)
#
# Needs: Android SDK with NDK 28.x, platform 35, build-tools, cmake 3.31 (all
# via sdkmanager), JDK 17, and generated/default from a host build (codegen).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_SRC="${REXSDK_DIR:-$ROOT/../rexglue-sdk}"
ANDROID_SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
NDK="${ANDROID_NDK:-$(ls -d "$ANDROID_SDK"/ndk/28.* 2>/dev/null | tail -1)}"
CMAKE="${CMAKE:-$(ls -d "$ANDROID_SDK"/cmake/3.3*/bin/cmake 2>/dev/null | tail -1)}"
NINJA="$(dirname "$CMAKE")/ninja"
BUILD="${BUILD_DIR:-$ROOT/out/build/android-arm64}"
CONFIG="${CONFIG:-Release}"
step="${1:-all}"

# Host rexglue CLI for the codegen step (a host build of the patched SDK, else
# the prebuilt SDK's bin/rexglue).
HOST_TOOL="${REXGLUE_HOST_TOOL:-$( (ls "$SDK_SRC"/out/build/linux-amd64/src/rexglue/rexglue "$ROOT"/../sdk-0.10.0/linux-amd64/bin/rexglue 2>/dev/null || true) | head -1)}"
# rexglue 0.10.0 ignores [analysis] max_jump_table_entries in the manifest
# (SDK patch 0005 fixes that); the environment override reaches both tools.
export REX_MAX_JUMP_TABLE_ENTRIES=519

configure() {
  "$CMAKE" -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_MAKE_PROGRAM="$NINJA" -DREXGLUE_HOST_TOOL="$HOST_TOOL" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DANDROID_STL=c++_shared \
    -DCMAKE_BUILD_TYPE="$CONFIG" -DREXSDK_DIR="$SDK_SRC" \
    -DREXGLUE_USE_VULKAN=ON -DREXGLUE_USE_D3D12=OFF -DREXGLUE_ENABLE_TRACY=OFF \
    -DREXGLUE_BUILD_TESTS=OFF -DREXGLUE_RECOMP_DEBUG_INFO=none -Wno-dev
}
native() {
  "$CMAKE" --build "$BUILD" --target crackdown2 --target rexgpu-xenos -j"${JOBS:-$(nproc)}"
}
cmake_build_plugin() {
  "$CMAKE" --build "$BUILD" --target rexgpu-xenos --target rexruntime -j"${JOBS:-$(nproc)}"
}
stage() {
  local jni="$ROOT/android/app/src/main/jniLibs/arm64-v8a"
  mkdir -p "$jni"
  # The GPU plugin is not a link dependency of the game, so the copy beside the
  # game in $BUILD can be stale; take it (and the runtime) from the SDK output.
  cmake_build_plugin
  cp -v "$BUILD/libmain.so" "$jni/"
  cp -v "$SDK_SRC/out/android-arm64/librexgpu-xenos.so" "$jni/"
  cp -v "$SDK_SRC/out/android-arm64/librexruntime.so" "$jni/"
  cp -v "$SDK_SRC/out/android-arm64/libSDL3.so" "$jni/"
  cp -v "$NDK"/toolchains/llvm/prebuilt/*/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so "$jni/"
}
apk() {
  stage
  (cd "$ROOT/android" && ./gradlew --no-daemon assembleRelease -PsdlJavaDir="$SDK_SRC/thirdparty/sdl3/android-project/app/src/main/java")
  ls -la "$ROOT/android/app/build/outputs/apk/release/"*.apk
}
install_apk() {
  adb install -r "$ROOT/android/app/build/outputs/apk/release/app-release.apk"
}
case "$step" in
  configure) configure ;;
  native) native ;;
  apk) apk ;;
  install) install_apk ;;
  all) configure; native; apk ;;
  *) echo "unknown step $step" >&2; exit 2 ;;
esac
