# KittyMemory

Dedicated library for runtime code patching & some memory utilities for both Android and iOS.

KittyMemory now depends on [Keystone Assembler](https://github.com/keystone-engine/keystone) for MemoryPatch::createWithAsm.

Prebuilt Keystone binaries are already included [Here](KittyMemory/Deps/Keystone/), However if you want to build them yourself you can use the scripts [build-android.sh](Deps/keystone-build-android.sh) & [build-ios.sh](Deps/keystone-build-ios.sh).

If for any reason you don't want to use Keystone and MemoryPatch::createWithAsm then add definition kNO_KEYSTONE to your project cpp flags.

Check [Android example](example-android/README.md) & [iOS example](example-ios/README.md) for how to use & build.