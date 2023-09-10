LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := KittyMemory

KITTYMEMORY_PATH = ../KittyMemory

KITTYMEMORY_SRC = $(KITTYMEMORY_PATH)/KittyMemory.cpp \
$(KITTYMEMORY_PATH)/MemoryPatch.cpp \
$(KITTYMEMORY_PATH)/MemoryBackup.cpp \
$(KITTYMEMORY_PATH)/KittyUtils.cpp \
$(KITTYMEMORY_PATH)/KittyScanner.cpp \
$(KITTYMEMORY_PATH)/KittyArm64.cpp

LOCAL_SRC_FILES := $(KITTYMEMORY_SRC) example.cpp

LOCAL_C_INCLUDES += $(KITTYMEMORY_PATH)/../

include $(BUILD_SHARED_LIBRARY)