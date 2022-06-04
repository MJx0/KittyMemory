#include "KittyScanner.h"

#include "KittyMemory.h"

using KittyMemory::ProcMap;

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

    uintptr_t find_from_lib(const char *name, const char *pattern, const char *mask)
    {
        if (!name || !pattern || !mask)
            return 0;

        ProcMap libMap = KittyMemory::getLibraryMap(name);
        if(!libMap.isValid()) return 0;

        return find((uintptr_t)libMap.startAddr, (size_t)libMap.length, pattern, mask);
    }

}