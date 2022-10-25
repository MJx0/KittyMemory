TARGET = iphone:clang:latest:10.0
ARCHS  = arm64 arm64e
DEBUG  = 0
FINALPACKAGE = 1

_NO_SUBSTRATE = 0
_IGNORE_WARNINGS = 1

KittyMemoryPath = ../KittyMemory


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = example

$(TWEAK_NAME)_CCFLAGS = -std=c++17 -fno-rtti

ifeq ($(_NO_SUBSTRATE), 1)
$(TWEAK_NAME)_CCFLAGS += -d_NO_SUBSTRATE_LINK
else
$(TWEAK_NAME)_LIBRARIES += substrate
endif

ifeq ($(_IGNORE_WARNINGS), 1)
$(TWEAK_NAME)_CCFLAGS += -w
endif

$(TWEAK_NAME)_FILES = Tweak.xm $(wildcard $(KittyMemoryPath)/*.cpp)

$(TWEAK_NAME)_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk