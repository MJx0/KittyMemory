## build for rootful/rootless
THEOS_PACKAGE_SCHEME = rootless
##THEOS_DEVICE_IP = 

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
THEOS_PACKAGE_DIR = rootless
else
THEOS_PACKAGE_DIR = rootful
endif

TARGET = iphone:clang:latest:10.0
ARCHS  = arm64 arm64e
DEBUG  = 0
FINALPACKAGE = 1

INSTALL_TARGET_PROCESSES = TargetApp


_NO_SUBSTRATE = 0
_IGNORE_WARNINGS = 1

KITTYMEMORY_PATH = ../KittyMemory


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = example

$(TWEAK_NAME)_CCFLAGS = -std=c++17 -fno-rtti

ifeq ($(_NO_SUBSTRATE), 1)
## define kNO_SUBSTRATE to not use MSHookMemory
$(TWEAK_NAME)_CCFLAGS += -DkNO_SUBSTRATE
else
$(TWEAK_NAME)_LIBRARIES += substrate
endif

ifeq ($(_IGNORE_WARNINGS), 1)
$(TWEAK_NAME)_CCFLAGS += -w
endif

$(TWEAK_NAME)_FILES = Tweak.xm $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

$(TWEAK_NAME)_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk