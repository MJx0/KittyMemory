APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
APP_PLATFORM := android-21
APP_STL := c++_static
APP_OPTIM := release
# define kITTYMEMORY_DEBUG in cpp flags for KITTY_LOGD debug outputs
APP_CPPFLAGS := -std=c++17 -fno-rtti -DkITTYMEMORY_DEBUG
APP_PIE := true
APP_LDFLAGS := -llog

APP_BUILD_SCRIPT := Android.mk