#!/bin/bash

set -e

# =========================
# Configuration
# =========================

KEYSTONE_REPO="https://github.com/keystone-engine/keystone.git"

IOS_DEPLOYMENT_TARGET="14.0"

BUILD_TYPE="Release"

JOBS="$(sysctl -n hw.ncpu)"

ARCH_TARGETS=(
    arm64
    arm64e
)

ROOT="$(pwd)"

SOURCE_PATH="${ROOT}/keystone"
BUILD_PATH="${ROOT}/_keystone_builds_ios"

GENERATOR="Unix Makefiles"

# =========================
# Check environment
# =========================

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: iOS builds require macOS/Xcode"
    exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: cmake not found"
    exit 1
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "ERROR: Xcode tools not found"
    exit 1
fi


# =========================
# Prepare source
# =========================

rm -rf "${BUILD_PATH}"
rm -rf "${SOURCE_PATH}"

echo "Cloning Keystone..."

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
    echo "Path: ${TARGET_BUILD_PATH}"
    echo "=============================="


    mkdir -p "${TARGET_BUILD_PATH}"

    pushd "${TARGET_BUILD_PATH}" >/dev/null


    cmake \
    -G "${GENERATOR}" \
    -S "${SOURCE_PATH}" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET}" \
    -DCMAKE_OSX_ARCHITECTURES="${ARCH_TARGET}" \
    -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
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
echo "Keystone iOS build complete"
echo "=============================="
