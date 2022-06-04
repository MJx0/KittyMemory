LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := KittyMemory

KITTYMEMORY_SRC = src/KittyMemory/KittyMemory.cpp \
src/KittyMemory/MemoryPatch.cpp \
src/KittyMemory/MemoryBackup.cpp \
src/KittyMemory/KittyUtils.cpp \
src/KittyMemory/KittyScanner.cpp \
src/KittyMemory/KittyArm64.cpp

LOCAL_SRC_FILES := src/main.cpp $(KITTYMEMORY_SRC)


include $(BUILD_SHARED_LIBRARY)