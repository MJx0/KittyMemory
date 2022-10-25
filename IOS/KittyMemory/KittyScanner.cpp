#include "KittyScanner.hpp"
#include "KittyUtils.hpp"

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

    std::vector<uintptr_t> findBytesAll(const mach_header *header, const char *segment,
                                        const char *bytes, const char *mask)
    {
        std::vector<uintptr_t> list;

        if (!header || !segment || !bytes || !mask)
            return list;

#if defined(__arm64e__) || defined(__arm64__) || defined(__aarch64__)
        const mach_header_64 *header_ = (const mach_header_64 *)header;
#else
        const mach_header *header_ = header;
#endif

        unsigned long seg_size = 0;
        uint8_t *start = getsegmentdata(header_, segment, &seg_size);
        if (!start || seg_size == 0)
            return list;

        uintptr_t curr_search_address = (uintptr_t)start;
        const size_t scan_size = strlen(mask);
        do {
            if (!list.empty()) curr_search_address = list.back() + scan_size;
            
            uintptr_t found = findInRange(curr_search_address, (uintptr_t)start+seg_size, bytes, mask);
            if (!found) break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const mach_header *header, const char *segment, const char *bytes, const char *mask)
    {
        if (!header || !segment || !bytes || !mask)
            return 0;

#if defined(__arm64e__) || defined(__arm64__) || defined(__aarch64__)
        const mach_header_64 *header_ = (const mach_header_64 *)header;
#else
        const mach_header *header_ = header;
#endif
        
        unsigned long seg_size = 0;
        uint8_t *start = getsegmentdata(header_, segment, &seg_size);
        if (!start || seg_size == 0)
            return 0;

        return findInRange((uintptr_t)start, (uintptr_t)start+seg_size, bytes, mask);
    }


    std::vector<uintptr_t> findHexAll(const mach_header *header, const char *segment, std::string hex, const char *mask) 
    {
        std::vector<uintptr_t> list;
        
        if (!header || !segment || !mask || !KittyUtils::validateHexString(hex)) return list;

        const size_t scan_size = strlen(mask);
        if((hex.length() / 2) != scan_size) return list;
        
        std::vector<char> bytes(scan_size);
        KittyUtils::fromHex(hex, &bytes[0]);

        list = findBytesAll(header, segment, bytes.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const mach_header *header, const char *segment, std::string hex, const char *mask) 
    {        
        if (!header || !segment || !mask || !KittyUtils::validateHexString(hex)) return 0;

        const size_t scan_size = strlen(mask);
        if((hex.length() / 2) != scan_size) return 0;
        
        std::vector<char> bytes(scan_size);
        KittyUtils::fromHex(hex, &bytes[0]);

        return findBytesFirst(header, segment, bytes.data(), mask);
    }


    std::vector<uintptr_t> findDataAll(const mach_header *header, const char *segment, const void *data, size_t size)
    {
        std::vector<uintptr_t> list;

        if (!header || !segment || !data || size < 1)
            return list;

        std::string mask(size, 'x');

        list = findBytesAll(header, segment, (const char *)data, mask.c_str());
        return list;
    }

    uintptr_t findDataFirst(const mach_header *header, const char *segment, const void *data, size_t size)
    {
        if (!header || !segment || !data || size < 1)
            return 0;

        std::string mask(size, 'x');

        return findBytesFirst(header, segment, (const char *)data, mask.c_str());
    }

}