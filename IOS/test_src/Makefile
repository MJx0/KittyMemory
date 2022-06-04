include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FWD_Kitty

FWD_Kitty_CCFLAGS = -std=c++11 -fno-rtti -w

FWD_Kitty_FILES = Tweak.xm \
$(wildcard KittyMemory/*.cpp)

FWD_Kitty_LIBRARIES += substrate

include $(THEOS_MAKE_PATH)/tweak.mk
