LOCAL_PATH := $(call my-dir)

KITTYMEMORY_PATH = $(LOCAL_PATH)/../KittyMemory
KITTYMEMORY_SRC = $(subst $(LOCAL_PATH),.,$(wildcard $(KITTYMEMORY_PATH)/*.cpp))

## Keystone static lib link
include $(CLEAR_VARS)
LOCAL_MODULE    := Keystone
LOCAL_SRC_FILES := $(KITTYMEMORY_PATH)/Deps/Keystone/libs-android/$(TARGET_ARCH_ABI)/libkeystone.a
include $(PREBUILT_STATIC_LIBRARY)

## Example lib
include $(CLEAR_VARS)

LOCAL_MODULE := KittyMemoryExample

LOCAL_SRC_FILES := example.cpp $(KITTYMEMORY_SRC)

## add keystone
LOCAL_STATIC_LIBRARIES := Keystone

include $(BUILD_SHARED_LIBRARY)