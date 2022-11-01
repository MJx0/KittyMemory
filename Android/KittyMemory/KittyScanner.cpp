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

    uintptr_t findInRange(const uintptr_t start, const uintptr_t end,
                   const char *pattern, const std::string& mask)
    {
        const size_t scan_size = mask.length();

        if (scan_size < 1 || ((start + scan_size) > end))
            return 0;

        const size_t length = end - start;

        for (size_t i = 0; i < length; ++i)
        {
            const uintptr_t current_end = start + i + scan_size;
            if (current_end > end)
                break;

            if (!compare(reinterpret_cast<const char *>(start + i), pattern, mask.c_str()))
                continue;

            return start + i;
        }
        return 0;
    }

    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end,
                                        const char *bytes, const std::string& mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end)
            return list;

        uintptr_t curr_search_address = start;
        const size_t scan_size = mask.length();
        do {
            if (!list.empty()) curr_search_address = list.back() + scan_size;
            
            uintptr_t found = findInRange(curr_search_address, end, bytes, mask);
            if (!found) break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask)
    {
        if (start >= end || !bytes || mask.empty())
            return 0;

        return findInRange(start, end, bytes, mask);
    }

    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask)
    {
        std::vector<uintptr_t> list;
        
        if (start >= end || mask.empty() || !KittyUtils::validateHexString(hex)) return list;

        const size_t scan_size = mask.length();
        if((hex.length() / 2) != scan_size) return list;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::fromHex(hex, &pattern[0]);

        list = findBytesAll(start, end, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask) 
    {        
        if (start >= end || mask.empty() || !KittyUtils::validateHexString(hex)) return 0;

        const size_t scan_size = mask.length();
        if((hex.length() / 2) != scan_size) return 0;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::fromHex(hex, &pattern[0]);

        return findBytesFirst(start, end, pattern.data(), mask);
    }


    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !data || size < 1)
            return list;

        std::string mask(size, 'x');

        list = findBytesAll(start, end, (const char *)data, mask);
        return list;
    }

    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        if (start >= end || !data || size < 1)
            return 0;

        std::string mask(size, 'x');

        return findBytesFirst(start, end, (const char *)data, mask);
    }

    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name)
    {
        uintptr_t string_loc = 0, string_xref = 0, fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || maps.empty())
            return fn;
        
        for (auto &it : maps)  {
            if (it.is_rx) {
                string_loc = KittyScanner::findDataFirst(it.startAddress, it.endAddress, name.data(), name.length());
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
                string_xref = KittyScanner::findDataFirst(it.startAddress, it.endAddress, &string_loc, sizeof(uintptr_t));
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