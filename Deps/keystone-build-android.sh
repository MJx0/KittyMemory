#!/bin/bash

## set ndk home
## NDK_HOME=

PWD=$(pwd)
SOURCE_PATH=${PWD}/keystone
BUILD_PATH=${PWD}/_keystone_builds_android
ARCH_TARGETS="armeabi-v7a arm64-v8a x86 x86_64"

rm -rf ${BUILD_PATH}

git clone https://github.com/keystone-engine/keystone.git keystone

for ARCH_TARGET in ${ARCH_TARGETS}
do
    TARGET_BUILD_PATH=${BUILD_PATH}/${ARCH_TARGET}/build
    echo "~: Building ${ARCH_TARGET} :~"
    echo "~: Path: ${TARGET_BUILD_PATH} :~"

    mkdir -p ${TARGET_BUILD_PATH}
    cd ${TARGET_BUILD_PATH}

    cmake ${SOURCE_PATH} -G"Unix Makefiles" \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_SYSTEM_VERSION=21 \
    -DCMAKE_ANDROID_NDK=${NDK_HOME} \
    -DCMAKE_ANDROID_ARCH_ABI=${ARCH_TARGET} \
    -DCMAKE_ANDROID_STL_TYPE=c++_static \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=0

    make -j32

    cd -

    cp ${TARGET_BUILD_PATH}/llvm/lib/libkeystone.a ${BUILD_PATH}/${ARCH_TARGET}
    echo "Binary built ${BUILD_PATH}/${ARCH_TARGET}/libkeystone.a"
done
