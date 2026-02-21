#!/usr/bin/env bash
set -e

# ===============================
# Config
# ===============================
NDK_PATH="${NDK_HOME}"
BUILD_TYPE=Release
ANDROID_API=21
ABIs=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

CMAKE=cmake
GENERATOR="Ninja"

CMAKE_BUILD_DIR=cmake_build
NDK_BUILD_DIR=ndk_build

# ===============================
# Detect cores
# ===============================
JOBS=$(($(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4) / 2))

# ===============================
# Validate
# ===============================
if [[ -z "NDK_PATH" ]]; then
  echo "ERROR: env variable NDK_HOME not set."
  exit 1
fi

# ===============================
# Menu
# ===============================
echo
echo "Select build system:"
echo "  [1] CMake"
echo "  [2] ndk-build"
echo

read -p "Enter choice (1 or 2): " CHOICE

case "$CHOICE" in
  1) BUILD_SYSTEM=cmake ;;
  2) BUILD_SYSTEM=ndk ;;
  *)
    echo "Invalid choice."
    exit 1
    ;;
esac

# ===============================
# CMake build
# ===============================
if [[ "$BUILD_SYSTEM" == "cmake" ]]; then
  for ABI in "${ABIs[@]}"; do
    echo "=================================="
    echo "CMake build - ABI $ABI (j$JOBS)"
    echo "=================================="

    $CMAKE -S . -B "${CMAKE_BUILD_DIR}/${ABI}" \
      -G "${GENERATOR}" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DCMAKE_TOOLCHAIN_FILE="${NDK_PATH}/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI=$ABI \
      -DANDROID_PLATFORM=android-${ANDROID_API} \
      -DANDROID_STL=c++_static

    $CMAKE --build "${CMAKE_BUILD_DIR}/${ABI}" -- -j${JOBS}
  done
fi

# ===============================
# ndk-build
# ===============================
if [[ "$BUILD_SYSTEM" == "ndk" ]]; then
  "$NDK_PATH/ndk-build" -j${JOBS} \
    NDK_PROJECT_PATH=. \
    APP_BUILD_SCRIPT=Android.mk \
    NDK_APPLICATION_MK=Application.mk \
    NDK_OUT="${NDK_BUILD_DIR}/obj" \
    NDK_LIBS_OUT="${NDK_BUILD_DIR}/libs"
fi
