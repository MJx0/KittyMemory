#!/bin/bash

set -e

# =========================
# Configuration
# =========================

# Override manually if needed
NDK_HOME=""

# Keystone source
KEYSTONE_REPO="https://github.com/keystone-engine/keystone.git"

# Build settings
ANDROID_PLATFORM=21
BUILD_TYPE=Release
JOBS="$(nproc)"

# Architectures
ARCH_TARGETS=(armeabi-v7a arm64-v8a x86 x86_64)

# Paths
ROOT="$(pwd)"
SOURCE_PATH="${ROOT}/keystone"
BUILD_PATH="${ROOT}/_keystone_builds_android"

GENERATOR="Unix Makefiles"


# =========================
# Find Android NDK
# =========================

find_ndk()
{
    local ndk=""

    if [[ -n "$NDK_HOME" ]] &&
       [[ -d "$NDK_HOME" ]]
    then
        echo "$NDK_HOME"
        return
    fi


    for v in \
        ANDROID_NDK_HOME \
        ANDROID_NDK \
        NDK_HOME
    do
        if [[ -n "${!v:-}" ]] &&
           [[ -d "${!v}" ]]
        then
            echo "${!v}"
            return
        fi
    done


    for sdk in \
        ANDROID_HOME \
        ANDROID_SDK_ROOT \
        ANDROID_SDK \
        ANDROID_SDK_HOME
    do
        if [[ -n "${!sdk:-}" ]] &&
           [[ -d "${!sdk}/ndk" ]]
        then
            local latest

            latest="$(
                find "${!sdk}/ndk" \
                    -mindepth 1 \
                    -maxdepth 1 \
                    -type d \
                    -printf "%f\n" |
                sort -V |
                tail -1
            )"

            if [[ -n "$latest" ]]; then
                echo "${!sdk}/ndk/${latest}"
                return
            fi
        fi
    done

    return 1
}


# =========================
# Setup
# =========================

if [[ -z "$NDK_HOME" ]]; then
    NDK_HOME="$(find_ndk)" || {
        echo "ERROR: Android NDK not found"
        exit 1
    }
fi

echo "NDK: ${NDK_HOME}"


# =========================
# Prepare source
# =========================

rm -rf "${BUILD_PATH}"
rm -rf "${SOURCE_PATH}"

git clone "${KEYSTONE_REPO}" "${SOURCE_PATH}"


# =========================
# Build
# =========================

for ARCH_TARGET in "${ARCH_TARGETS[@]}"
do
    TARGET_BUILD_PATH="${BUILD_PATH}/${ARCH_TARGET}/build"

    echo
    echo "=============================="
    echo "Building ${ARCH_TARGET}"
    echo "=============================="

    mkdir -p "${TARGET_BUILD_PATH}"

    pushd "${TARGET_BUILD_PATH}" >/dev/null

    cmake \
    -G "${GENERATOR}" \
    -S "${SOURCE_PATH}" \
    -DCMAKE_TOOLCHAIN_FILE="${NDK_HOME}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="${ARCH_TARGET}" \
    -DANDROID_PLATFORM="android-${ANDROID_PLATFORM}" \
    -DANDROID_STL="c++_static" \
    -DBUILD_LIBS_ONLY=1 \
    -DBUILD_SHARED_LIBS=0 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

    make -j"${JOBS}"

    popd >/dev/null


    cp \
        "${TARGET_BUILD_PATH}/llvm/lib/libkeystone.a" \
        "${BUILD_PATH}/${ARCH_TARGET}/libkeystone.a"

    echo "Built ${BUILD_PATH}/${ARCH_TARGET}/libkeystone.a"
done


echo
echo "=============================="
echo "Build complete"
echo "=============================="