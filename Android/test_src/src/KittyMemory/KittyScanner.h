#pragma once

#include <string>
#include <cstdint>

namespace KittyScanner
{

    bool compare(const char *data, const char *pattern, const char *mask);

    uintptr_t find(const uintptr_t start, const size_t size, const char *pattern, const char *mask);

    uintptr_t find_from_lib(const char *name, const char *pattern, const char *mask);

}