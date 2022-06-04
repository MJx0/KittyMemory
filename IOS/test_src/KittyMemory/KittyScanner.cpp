#include "KittyScanner.hpp"

// refs 
// https://github.com/learn-more/findpattern-bench

namespace KittyScanner
{

    bool compare(const char *data, const char *pattern, const char *mask)
    {
        for (; *mask; ++mask, ++data, ++pattern)
        {
            if (*mask == 'x' && *data != *pattern)
                return false;
        }

        return !*mask;
    }

    uintptr_t find(const uintptr_t start, const size_t size, const char *pattern, const char *mask)
    {
        for (size_t i = 0; i < size; ++i)
        {
            if (!compare(reinterpret_cast<const char *>(start + i), pattern, mask))
                continue;

            return start + i;
        }
        return 0;
    }

    uintptr_t find_from_segment64(const mach_header_64 *header, const char *seg, const char *pattern, const char *mask)
    {
        if (!header || !seg || !pattern || !mask)
            return 0;

        unsigned long size = 0;
        uint8_t *start = getsegmentdata(header, seg, &size);
        if (!start || size == 0)
            return 0;

        return find((uintptr_t)start, size, pattern, mask);
    }

}