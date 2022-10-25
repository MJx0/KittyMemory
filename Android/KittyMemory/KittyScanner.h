#pragma once

#include <string>
#include <cstdint>
#include <vector>

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

    bool compare(const char *data, const char *pattern, const char *mask);

    uintptr_t findInRange(const uintptr_t start, const size_t end, const char *pattern, const char *mask);

    // scan for direct bytes and return first result
    std::vector<uintptr_t> findBytesAll(const KittyMemory::ProcMap& map, const char *bytes, const char *mask);
    // scan for direct bytes and return all result
    uintptr_t findBytesFirst(const KittyMemory::ProcMap& map, const char *bytes, const char *mask);

    // scan for hex bytes and return first result
    std::vector<uintptr_t> findHexAll(const KittyMemory::ProcMap& map, std::string hex, const char *mask);
    // scan for hex bytes and return all result
    uintptr_t findHexFirst(const KittyMemory::ProcMap& map, std::string hex, const char *mask);

    // scan for data and return first result
    std::vector<uintptr_t> findDataAll(const KittyMemory::ProcMap &map, const void *data, size_t size);
    // scan for data and return all result
    uintptr_t findDataFirst(const KittyMemory::ProcMap &map, const void *data, size_t size);

    // search for string "name" references to find the JNINativeMethod array
    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name);

}