APP_ABI := armeabi-v7a arm64-v8a x86
APP_PLATFORM := android-19
APP_STL := c++_static
APP_OPTIM := release
APP_CPPFLAGS := -std=c++17 -fno-rtti -DkITTYMEMORY_DEBUG
APP_PIE := true
APP_LDFLAGS := -llog

APP_BUILD_SCRIPT := Android.mk