# KittyMemory Android Example

<h3>This is an example android shared lib.</h3>

Requires C++11 or above.</br>
Android API 21 or above for keystone linking.

See how to use KittyMemory in [example.cpp](example.cpp).

<h3>Clone:</h3>

```
git clone --recursive https://github.com/MJx0/KittyMemory.git
```

<h3>How to build:</h3>

<h4>NDK Build:</h4>

- In your Android.mk somewhere at top, define:

```make
## it's better to use relative path to $(LOCAL_PATH) and then use subst
KITTYMEMORY_PATH = path/to/KittyMemory
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)
```

- Inlcude Keystone static lib:

```make
include $(CLEAR_VARS)
LOCAL_MODULE    := Keystone
LOCAL_SRC_FILES := $(KITTYMEMORY_PATH)/Deps/Keystone/libs-android/$(TARGET_ARCH_ABI)/libkeystone.a
include $(PREBUILT_STATIC_LIBRARY)
```

- Add KittyMemory source files:

```make
LOCAL_SRC_FILES := example.cpp $(KITTYMEMORY_SRC)
```

- Finally add keystone static lib:

```make
LOCAL_STATIC_LIBRARIES := Keystone
```

You can check example here [Android.mk](Android.mk).

<h4>CMake Build:</h4>

- In your CMakeLists.txt somewhere at top, define:

```cmake
set(KITTYMEMORY_PATH path/to/KittyMemory)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)
```

- Inlcude Keystone static lib:

```cmake
set(KEYSTONE_LIB ${KITTYMEMORY_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)
```

- Add KittyMemory source files:

```cmake
add_library(YourProjectName SHARED example.cpp ${KITTYMEMORY_SRC})
```

- Finally add keystone static lib:

```cmake
target_link_libraries(YourProjectName ${KEYSTONE_LIB})
## or
link_libraries(${KEYSTONE_LIB})
```

You can check example here [CMakeLists.txt](CMakeLists.txt).

NOTE:
If you don't want to link keystone and use MemoryPatch::createWithAsm then add definition kNO_KEYSTONE to your cpp flags.
