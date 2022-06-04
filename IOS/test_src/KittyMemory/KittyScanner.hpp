#pragma once

#include <string>
#include <cstdint>

#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>

namespace KittyScanner
{

    bool compare(const char *data, const char *pattern, const char *mask);

    uintptr_t find(const uintptr_t start, const size_t size, const char *pattern, const char *mask);

    uintptr_t find_from_segment64(const mach_header_64 *header, const char *seg, const char *pattern, const char *mask);

}