LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := KittyMemory

KittyMemoryPath = ../KittyMemory

KITTYMEMORY_SRC = $(KittyMemoryPath)/KittyMemory.cpp \
$(KittyMemoryPath)/MemoryPatch.cpp \
$(KittyMemoryPath)/MemoryBackup.cpp \
$(KittyMemoryPath)/KittyUtils.cpp \
$(KittyMemoryPath)/KittyScanner.cpp \
$(KittyMemoryPath)/KittyArm64.cpp

LOCAL_SRC_FILES := $(KITTYMEMORY_SRC) example.cpp

LOCAL_C_INCLUDES += $(KittyMemoryPath)/../

include $(BUILD_SHARED_LIBRARY)