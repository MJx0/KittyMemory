# KittyMemory

Dedicated library for runtime code patching, memory scanning and some more memory utilities for both Android and iOS.

KittyMemory now depends on [Keystone Assembler](https://github.com/keystone-engine/keystone) for MemoryPatch::createWithAsm.

Prebuilt Keystone binaries are already included [Here](KittyMemory/Deps/Keystone/), However if you want to build them yourself you can use the scripts [build-android.sh](Deps/keystone-build-android.sh) & [build-ios.sh](Deps/keystone-build-ios.sh).

If for any reason you don't want to use Keystone and MemoryPatch::createWithAsm then add definition kNO_KEYSTONE to your project cpp flags.

Check [Android example](example-android/README.md) & [iOS example](example-ios/README.md) for how to use & build.

## Documentation

[![Android API Docs](https://img.shields.io/badge/Android-Doxygen-green?style=for-the-badge&logo=android)](https://MJx0.github.io/KittyMemory/android/index.html)
[![iOS API Docs](https://img.shields.io/badge/iOS-Doxygen-blue?style=for-the-badge&logo=apple)](https://MJx0.github.io/KittyMemory/ios/index.html)
