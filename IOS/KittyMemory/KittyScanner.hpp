#pragma once

#include <string>
#include <cstdint>
#include <vector>

#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>

namespace KittyScanner
{
    bool compare(const char *data, const char *pattern, const char *mask);

    uintptr_t findInRange(const uintptr_t start, const size_t end, const char *pattern, const char *mask);

    // scan for direct bytes inside a segment and return first result
    std::vector<uintptr_t> findBytesAll(const mach_header *header, const char *segment, const char *bytes, const char *mask);
    // scan for direct bytes inside a segment and return all result
    uintptr_t findBytesFirst(const mach_header *header, const char *segment, const char *bytes, const char *mask);

    // scan for hex bytes inside a segment and return first result
    std::vector<uintptr_t> findHexAll(const mach_header *header, const char *segment, std::string hex, const char *mask);
    // scan for hex bytes inside a segment and return all result
    uintptr_t findHexFirst(const mach_header *header, const char *segment, std::string hex, const char *mask);

    // scan for data inside a segment and return first result
    std::vector<uintptr_t> findDataAll(const mach_header *header, const char *segment, const void *data, size_t size);
    // scan for data inside a segment and return all result
    uintptr_t findDataFirst(const mach_header *header, const char *segment, const void *data, size_t size);

}