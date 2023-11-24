# KittyMemory iOS Example

<h3>This is an example theos tweak.</h3>

Requires C++11 or above.

See how to use KittyMemory in [Tweak.mm](Tweak.mm).

<h3>Clone:</h3>

```
git clone --recursive https://github.com/MJx0/KittyMemory.git
```

<h3>How to build:</h3>

- In your tweak Makefile somewhere at top, define:

```make
KITTYMEMORY_PATH = path/to/KittyMemory
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)
```

- Add KittyMemory source files to your tweak files:

```make
$(TWEAK_NAME)_FILES = Tweak.mm $(KITTYMEMORY_SRC)
```

- Finally add keystone static lib to your tweak obj files:

```make
$(TWEAK_NAME)_OBJ_FILES = $(KITTYMEMORY_PATH)/Deps/Keystone/libs-ios/$(THEOS_CURRENT_ARCH)/libkeystone.a
```

You can check example here [Makefile](Makefile).
