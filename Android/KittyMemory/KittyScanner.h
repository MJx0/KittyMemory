#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

#include "KittyMemory.h"

namespace KittyScanner
{
    class RegisterNativeFn
    {
    public:
        char *name;
        char *signature;
        void *fnPtr;

        RegisterNativeFn() : name(nullptr), signature(nullptr), fnPtr(nullptr) {}
        inline bool isValid() const { return (name != nullptr && signature != nullptr && fnPtr != nullptr); }
    };

    // scan for direct bytes and return first result
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask);
    // scan for direct bytes and return all result
    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask);

    // scan for hex bytes and return first result
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask);
    // scan for hex bytes and return all result
    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask);

    // scan for data and return first result
    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size);
    // scan for data and return all result
    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

    // search for string "name" references to find the JNINativeMethod array
    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name);

    // lookup symbol name in a loaded shared object
    // returns the absolute address of the symbol
    uintptr_t findSymbol(const KittyMemory::ProcMap &baseMap, const std::string &symbol_name);

    // lookup symbol name in a loaded shared object
    // returns the absolute address of the symbol
    uintptr_t findSymbol(const std::string &lib, const std::string &symbol_name);

    // lookup symbol name in all loaded shared objects
    // returns a vector of symbol absolute address and the library pathname where the symbol was found in
    std::vector<std::pair<uintptr_t, std::string>> findSymbolAll(const std::string &symbol_name);
}