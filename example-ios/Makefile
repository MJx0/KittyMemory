## build for rootful/rootless/roothide
THEOS_PACKAGE_SCHEME = rootless
#THEOS_DEVICE_IP =

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
THEOS_PACKAGE_DIR = rootless
else ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
THEOS_PACKAGE_DIR = roothide
else
THEOS_PACKAGE_DIR = rootful
endif

## https://theos.dev/docs/arm64e-deployment
## export DEVELOPER_DIR=/Applications/Xcode-11.7.app/Contents/Developer
TARGET = iphone:clang:latest:14.0
ARCHS  = arm64 arm64e
DEBUG  = 0
FINALPACKAGE = 1

INSTALL_TARGET_PROCESSES = TargetApp

_NO_KEYSTONE = 0
_IGNORE_WARNINGS = 1

KITTYMEMORY_PATH = ../KittyMemory
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = example

# define kITTYMEMORY_DEBUG in cpp flags if you want KITTY_LOGD debug outputs
$(TWEAK_NAME)_CCFLAGS = -std=c++17 -DkITTYMEMORY_DEBUG

ifeq ($(_NO_KEYSTONE), 1)
## define _NO_KEYSTONE to not use Keystone MemoryPatch::createWithAsm
$(TWEAK_NAME)_CCFLAGS += -DkNO_KEYSTONE
else
## link keystone lib for MemoryPatch::createWithAsm
$(TWEAK_NAME)_OBJ_FILES = $(KITTYMEMORY_PATH)/Deps/Keystone/libs-ios/$(THEOS_CURRENT_ARCH)/libkeystone.a
endif

ifeq ($(_IGNORE_WARNINGS), 1)
$(TWEAK_NAME)_CCFLAGS += -w
endif

$(TWEAK_NAME)_FILES = Tweak.mm $(KITTYMEMORY_SRC)

$(TWEAK_NAME)_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk