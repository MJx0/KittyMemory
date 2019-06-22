APP_ABI := armeabi-v7a arm64-v8a x86
APP_PLATFORM := android-16
APP_STL := c++_static
APP_OPTIM := release
APP_CPPFLAGS := -std=c++14 -fno-rtti -fno-exceptions -DNDEBUG -Wall -fpermissive -fpic
APP_LDFLAGS := -llog

APP_BUILD_SCRIPT := Android.mk