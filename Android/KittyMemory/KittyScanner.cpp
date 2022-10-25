#include "KittyScanner.h"

#include "KittyMemory.h"
#include "KittyUtils.h"

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

    uintptr_t findInRange(const uintptr_t start, uintptr_t end,
                   const char *pattern, const char *mask)
    {
        const size_t scan_size = strlen(mask);

        if ((start + scan_size) > end)
            return 0;

        const size_t length = end - start;

        for (size_t i = 0; i < length; ++i)
        {
            const uintptr_t current_end = start + i + scan_size;
            if (current_end > end)
                break;

            if (!compare(reinterpret_cast<const char *>(start + i), pattern, mask))
                continue;

            return start + i;
        }
        return 0;
    }

    std::vector<uintptr_t> findBytesAll(const KittyMemory::ProcMap &map,
                                        const char *bytes, const char *mask)
    {
        std::vector<uintptr_t> list;

        if (!map.isValid())
            return list;

        uintptr_t curr_search_address = map.startAddress;
        const size_t scan_size = strlen(mask);
        do {
            if (!list.empty()) curr_search_address = list.back() + scan_size;
            
            uintptr_t found = findInRange(curr_search_address, map.endAddress, bytes, mask);
            if (!found) break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const KittyMemory::ProcMap &map, const char *bytes, const char *mask)
    {
        if (!map.isValid() || !bytes || !mask)
            return 0;

        return findInRange(map.startAddress, map.endAddress, bytes, mask);
    }


    std::vector<uintptr_t> findHexAll(const KittyMemory::ProcMap& map, std::string hex, const char *mask) 
    {
        std::vector<uintptr_t> list;
        
        if (!map.isValid() || !mask || !KittyUtils::validateHexString(hex)) return list;

        const size_t scan_size = strlen(mask);
        if((hex.length() / 2) != scan_size) return list;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::fromHex(hex, &pattern[0]);

        list = findBytesAll(map, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const KittyMemory::ProcMap& map, std::string hex, const char *mask) 
    {        
        if (!map.isValid() || !mask || !KittyUtils::validateHexString(hex)) return 0;

        const size_t scan_size = strlen(mask);
        if((hex.length() / 2) != scan_size) return 0;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::fromHex(hex, &pattern[0]);

        return findBytesFirst(map, pattern.data(), mask);
    }


    std::vector<uintptr_t> findDataAll(const KittyMemory::ProcMap &map, const void *data, size_t size)
    {
        std::vector<uintptr_t> list;

        if (!map.isValid() || !data || size < 1)
            return list;

        std::string mask(size, 'x');

        list = findBytesAll(map, (const char *)data, mask.c_str());
        return list;
    }

    uintptr_t findDataFirst(const KittyMemory::ProcMap &map, const void *data, size_t size)
    {
        if (!map.isValid() || !data || size < 1)
            return 0;

        std::string mask(size, 'x');

        return findBytesFirst(map, (const char *)data, mask.c_str());
    }

    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name)
    {
        uintptr_t string_loc = 0, string_xref = 0, fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || maps.empty())
            return fn;
        
        for (auto &it : maps)  {
            if (it.is_rx) {
                string_loc = KittyScanner::findDataFirst(it, name.data(), name.length());
                if (string_loc) break;
            }
        }

        if (!string_loc) {
            KITTY_LOGE("couldn't find string (%s) in selected maps", name.c_str());
            return fn;
        }

        KITTY_LOGI("string (%s) at %p", name.c_str(), (void*)string_loc);

        for (auto &it : maps) {
            if (it.is_rw) {
                string_xref = KittyScanner::findDataFirst(it, &string_loc, sizeof(uintptr_t));
                if (!string_xref) continue;

                KITTY_LOGI("string at (%p) referenced at %p", (void *)string_loc, (void *)string_xref);
                
                fn_loc = string_xref;
                break;
            }
        }

        if(!fn_loc) return fn;

        memcpy(&fn, (void *)fn_loc, sizeof(RegisterNativeFn));
        return fn;
    }

}