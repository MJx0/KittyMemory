# KittyMemory Android Example

<h3>This is an example android shared lib.</h3>

Requires C++11 or above.</br>
Android API 21 or above for keystone linking.

See how to use KittyMemory in [example.cpp](example.cpp).

<h3>How to build:</h3>

- In your Android.mk somewhere at top, define:

```
KITTYMEMORY_PATH = path/to/KittyMemory
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)
```

- Inlcude Keystone static lib:

```
include $(CLEAR_VARS)
LOCAL_MODULE    := Keystone
LOCAL_SRC_FILES := $(KITTYMEMORY_PATH)/Deps/Keystone/libs-android/$(TARGET_ARCH_ABI)/libkeystone.a
include $(PREBUILT_STATIC_LIBRARY)
```

- Add KittyMemory source files:

```
LOCAL_SRC_FILES := example.cpp $(KITTYMEMORY_SRC)
```

- Finally add keystone static lib:

```
LOCAL_STATIC_LIBRARIES := Keystone
```

You can check example here [Android.mk](Android.mk).
