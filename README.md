# KittyMemory

KittyMemory is a native C++ library for runtime memory patching, scanning, dumping, and module (ELF / Mach-O) introspection, targeting **Android** and **iOS**. It operates on the **current process**.

## Features

- **Memory patching & backup** — `MemoryPatch` / `MemoryBackup`: snapshot-then-modify-then-restore workflows for arbitrary code or data, built from raw bytes, a hex string, or hand-written assembly (via [Keystone](https://github.com/keystone-engine/keystone)).
- **Pattern scanning** — `KittyScanner::findBytesFirst/All`, `findHexFirst/All`, `findIdaPatternFirst/All`, `findDataFirst/All`: byte-mask, hex-mask, IDA-style (`"33 ? 55 66 ? 77 88 ? 99"`), and exact raw-value search, with a fast in-process mode and a safe syscall-based mode (`setPatternScanSafeMode`) that skips unmapped pages instead of crashing.
- **ELF introspection (Android)**
  - `ElfScanner` parses a loaded library's program headers, dynamic section, and symbol/hash tables directly out of memory (no need for the file on disk), including libraries mapped from inside a split APK/zip.
  - Symbol lookup covers both the live dynamic symbol table (`findSymbol`) and on-disk debug symbols (`dsymbols`, `findDebugSymbol` — for symbols not dynamically exported).
  - Segment discovery exposes the module's main segment (`baseSegment()`), all mapped segments (`segments()`), and its BSS segments (`bssSegments()`), each as a `KittyMemory::ProcMap`.
- **Native & Emulated solist walking (Android)**
  - `LinkerScanner` walks the Android dynamic linker's internal `solist` to enumerate every natively-loaded library.
  - `NativeBridgeScanner` does the same for libraries running under an ISA-emulation layer (libhoudini, libndk_translation), including detecting the implementation and the native-bridge callback table (`nbItfData()`); `NativeBridgeLinker` lets you `dlopen`/`dlsym`/`dlclose`/`dladdr`/`dl_iterate_phdr` directly into those emulated libraries.
- **Mach-O introspection (iOS)**
  - `MachOImage` resolves a loaded image (app binary or a named framework/dylib, via `findMachOImage`/`getMainImage`/`getAllImages`).
  - Symbol lookup via `symbols()` (all non-STAB symbols) and `findSymbol(name)`.
  - Segment/section discovery via `segments()`/`sections()` (all, keyed by name) and `findSegment("__TEXT")`/`findSection("__TEXT", "__text")`.
  - `KittyMemory::getAbsoluteAddress` turns an on-disk offset into a live ASLR-slid address.
- **Memory maps (Android)**
  - `KittyMemory::ProcMap` models one `/proc/self/maps` entry (bounds, permissions, backing file).
  - `getAllMaps()` / `getMaps(EProcMapFilter, name)` (`Equal`/`Contains`/`StartWith`/`EndWith`/`Regex`) / `getAddressMap(address)` enumerate and filter process maps
  - `getFileMappings(path)` groups a backing file's mappings into contiguous runs (handling files split across multiple mappings).
- **Memory regions (iOS)**
  - `KittyMemory::mem_range_info_t` models one Mach `vm_region` (bounds, protection/max-protection, name).
  - `getAllRegions()` / `getRegions(EMemRegionFilter, name)` / `getAddressRegion(address)` enumerate and filter memory regiosn.
  - `getFileMappings(path)` groups a backing file's mappings into contiguous runs, same semantics as the Android version.
- **Instruction decoding** — `KittyAsm` (namespaces `KittyArm32` / `KittyArm64`) is a lightweight ARM32/ARM64 instruction decoder.
- **Memory dump utilities (Android & iOS)**
  - `KittyMemory::dumpMemToDisk` dumps an arbitrary address range to a file.
  - `KittyMemory::dumpFileMappingsToDisk` dumps every contiguous mapping of a memory-mapped file (e.g. Unity's `global-metadata.dat`) to disk, one output file per mapping if it's split.
- **ELF dumping (Android)** — `ElfScanner::dumpToDisk` writes the loaded library's ELF image straight from memory to disk, useful for pulling packed/decrypted or renamed libraries.
- **`KittyUtils` Various utilities**.

## Requirements

- C++17 or newer.
- Android: NDK, API level 21 or newer.
- iOS: [Theos](https://theos.dev/) or xcode for building tweaks/dylibs, deployment target iOS 14.0+.
- [Keystone Assembler](https://github.com/keystone-engine/keystone) — only needed for `MemoryPatch::createWithAsm`. Prebuilt static libraries for both platforms are already vendored under [`KittyMemory/Deps/Keystone`](KittyMemory/Deps/Keystone/); You can rebuild them yourself with `Deps/Keystone/build_keystone_android.sh` / `build_keystone_ios.sh`. If you don't want Keystone dependency then Define `kNO_KEYSTONE` in your project's C++ flags (this removes `createWithAsm`).

See [example-android/README.md](example-android/README.md) and [example-ios/README.md](example-ios/README.md) for full NDK/CMake and Theos build instructions.

## Documentation

[![Android API Docs](https://img.shields.io/badge/Android-Doxygen-green?style=for-the-badge&logo=android)](https://MJx0.github.io/KittyMemory/android/index.html)

[![iOS API Docs](https://img.shields.io/badge/iOS-Doxygen-blue?style=for-the-badge&logo=apple)](https://MJx0.github.io/KittyMemory/ios/index.html)
