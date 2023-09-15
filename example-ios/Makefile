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
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = example

# define kITTYMEMORY_DEBUG in cpp flags if you want KITTY_LOGD debug outputs
$(TWEAK_NAME)_CCFLAGS = -std=c++17 -fno-rtti -DkITTYMEMORY_DEBUG

ifeq ($(_NO_SUBSTRATE), 1)
## define kNO_SUBSTRATE to not use MSHookMemory
$(TWEAK_NAME)_CCFLAGS += -DkNO_SUBSTRATE
endif

ifeq ($(_IGNORE_WARNINGS), 1)
$(TWEAK_NAME)_CCFLAGS += -w
endif

$(TWEAK_NAME)_FILES = Tweak.mm $(KITTYMEMORY_SRC)

$(TWEAK_NAME)_FRAMEWORKS = Foundation

## add keystone static lib
$(TWEAK_NAME)_OBJ_FILES = $(KITTYMEMORY_PATH)/Deps/Keystone/libs-ios/$(THEOS_CURRENT_ARCH)/libkeystone.a

include $(THEOS_MAKE_PATH)/tweak.mk