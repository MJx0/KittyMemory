#include "KittyPtrValidator.hpp"

#ifdef __APPLE__

bool KittyPtrValidator::_findRegion(uintptr_t addr, RegionInfo *region)
{
    if (!use_cache_)
    {
        vm_address_t address = addr & ~(page_size_ - 1);
        vm_size_t size = 0;
        natural_t nesting_depth = 0;
        vm_region_submap_short_info_data_64_t info{};
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        kern_return_t kret = vm_region_recurse_64(task_,
                                                  &address,
                                                  &size,
                                                  &nesting_depth,
                                                  (vm_region_recurse_info_t)&info,
                                                  &info_count);
        if (kret != KERN_SUCCESS)
            return false;

        bool readable = (info.protection & VM_PROT_READ) != 0;
        bool writable = (info.protection & VM_PROT_WRITE) != 0;
        bool executable = (info.protection & VM_PROT_EXECUTE) != 0;
        *region = RegionInfo(address, address + size, readable, writable, executable);
        return address <= addr && addr < address + size;
    }

    if (!cachedRegions_.empty())
    {
        if (last_region_index_ < cachedRegions_.size() && cachedRegions_[last_region_index_].start <= addr &&
            addr < cachedRegions_[last_region_index_].end)
        {
            *region = cachedRegions_[last_region_index_];
            return true;
        }

        size_t left = 0;
        size_t right = cachedRegions_.size();
        size_t best_match = right;

        while (left < right)
        {
            size_t mid = left + (right - left) / 2;
            if (cachedRegions_[mid].end <= addr)
            {
                left = mid + 1;
            }
            else
            {
                best_match = mid;
                right = mid;
            }
        }

        if (best_match < cachedRegions_.size() && cachedRegions_[best_match].start <= addr &&
            addr < cachedRegions_[best_match].end)
        {
            last_region_index_ = best_match;
            *region = cachedRegions_[best_match];
            return true;
        }
    }

    return false;
}

void KittyPtrValidator::refreshRegionCache()
{
    cachedRegions_.clear();
    vm_address_t address = 0;

    while (true)
    {
        vm_size_t size = 0;
        natural_t nesting_depth = 0;
        vm_region_submap_short_info_data_64_t info{};
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        kern_return_t kret = vm_region_recurse_64(task_,
                                                  &address,
                                                  &size,
                                                  &nesting_depth,
                                                  (vm_region_recurse_info_t)&info,
                                                  &info_count);
        if (kret != KERN_SUCCESS)
            break;

        bool readable = (info.protection & VM_PROT_READ) != 0;
        bool writable = (info.protection & VM_PROT_WRITE) != 0;
        bool executable = (info.protection & VM_PROT_EXECUTE) != 0;
        RegionInfo new_region(address, address + size, readable, writable, executable);

        if (!cachedRegions_.empty() && cachedRegions_.back().canMergeWith(new_region))
        {
            cachedRegions_.back().end = new_region.end;
        }
        else
        {
            cachedRegions_.emplace_back(new_region);
        }

        address += size;
    }

    if (!cachedRegions_.empty())
    {
        std::sort(cachedRegions_.begin(), cachedRegions_.end(), [](const RegionInfo &a, const RegionInfo &b) {
            return a.start < b.start;
        });
    }

    last_region_index_ = 0;
}

#else

bool KittyPtrValidator::_parseMapsLine(const char *line, RegionInfo *region)
{
    if (!line || *line == '\0')
        return false;

    char *endPtr;
    uintptr_t start = (uintptr_t)strtoull(line, &endPtr, 16);
    if (*endPtr != '-')
        return false;

    uintptr_t end = (uintptr_t)strtoull(endPtr + 1, &endPtr, 16);

    while (*endPtr == ' ')
        endPtr++;

    if (!endPtr[0] || !endPtr[1] || !endPtr[2])
        return false;

    *region = RegionInfo(start, end, endPtr[0] == 'r', endPtr[1] == 'w', endPtr[2] == 'x');
    return true;
}

bool KittyPtrValidator::_findRegion(uintptr_t addr, RegionInfo *out)
{
    addr = KittyUtils::untagHeepPtr(addr);
    if (!use_cache_)
    {
        bool found = false;

        char filePath[0xff] = {};
        snprintf(filePath, sizeof(filePath), "/proc/%d/maps", pid_);
        FILE *fp = fopen(filePath, "r");
        if (!fp)
            return false;

        char line[512];
        while (fgets(line, sizeof(line), fp))
        {
            RegionInfo region(0, 0, false, false, false);
            if (_parseMapsLine(line, &region))
            {
                if (addr >= region.start && addr < region.end)
                {
                    *out = region;
                    found = true;
                    break;
                }
            }
        }

        fclose(fp);
        return found;
    }

    if (!cachedRegions_.empty())
    {
        if (last_region_index_ < cachedRegions_.size())
        {
            const auto &last = cachedRegions_[last_region_index_];
            if (addr >= last.start && addr < last.end)
            {
                *out = last;
                return true;
            }
        }

        auto it = std::lower_bound(cachedRegions_.begin(),
                                   cachedRegions_.end(),
                                   addr,
                                   [](const RegionInfo &r, uintptr_t val) { return r.end <= val; });

        if (it != cachedRegions_.end() && addr >= it->start && addr < it->end)
        {
            *out = *it;
            last_region_index_ = std::distance(cachedRegions_.begin(), it);
            return true;
        }
    }

    return false;
}

void KittyPtrValidator::refreshRegionCache()
{
    cachedRegions_.clear();
    last_region_index_ = 0;

    char filePath[0xff] = {};
    snprintf(filePath, sizeof(filePath), "/proc/%d/maps", pid_);

    FILE *fp = fopen(filePath, "r");
    if (!fp)
        return;

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        RegionInfo region(0, 0, false, false, false);

        if (_parseMapsLine(line, &region))
        {
            if (!cachedRegions_.empty() && cachedRegions_.back().canMergeWith(region))
            {
                cachedRegions_.back().end = region.end;
            }
            else
            {
                cachedRegions_.emplace_back(region);
            }
        }
    }

    fclose(fp);

    if (!cachedRegions_.empty())
    {
        std::sort(cachedRegions_.begin(), cachedRegions_.end(), [](const RegionInfo &a, const RegionInfo &b) {
            return a.start < b.start;
        });
    }
}


#endif

bool KittyPtrValidator::isPtrReadable(uintptr_t ptr, size_t len)
{
    if (ptr == 0 || ptr + len < ptr)
        return false;

    ptr = KittyUtils::untagHeepPtr(ptr);

    uintptr_t end = ptr + len;
    RegionInfo region(0, 0, false, false, false);
    while (region.end < end)
    {
        if (!_findRegion(ptr, &region) || !region.readable)
            return false;

        ptr = region.end;
    }

    return true;
}

bool KittyPtrValidator::isPtrWritable(uintptr_t ptr, size_t len)
{
    if (ptr == 0 || ptr + len < ptr)
        return false;

    ptr = KittyUtils::untagHeepPtr(ptr);

    uintptr_t end = ptr + len;
    RegionInfo region(0, 0, false, false, false);
    while (region.end < end)
    {
        if (!_findRegion(ptr, &region) || !region.writable)
            return false;

        ptr = region.end;
    }

    return true;
}

bool KittyPtrValidator::isPtrExecutable(uintptr_t ptr, size_t len)
{
    if (ptr == 0 || ptr + len < ptr)
        return false;

    ptr = KittyUtils::untagHeepPtr(ptr);

    uintptr_t end = ptr + len;
    RegionInfo region(0, 0, false, false, false);
    while (region.end < end)
    {
        if (!_findRegion(ptr, &region) || !region.executable)
            return false;

        ptr = region.end;
    }

    return true;
}