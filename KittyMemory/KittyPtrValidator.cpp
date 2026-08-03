#include "KittyPtrValidator.hpp"

#ifdef __APPLE__

extern "C" kern_return_t mach_vm_region_recurse(vm_map_read_t target_task,
                                                mach_vm_address_t *address,
                                                mach_vm_size_t *size,
                                                natural_t *nesting_depth,
                                                vm_region_recurse_info_t info,
                                                mach_msg_type_number_t *infoCnt);

bool KittyPtrValidator::_findRegion(uintptr_t addr, RegionInfo *info_out)
{
    if (!use_cache_)
    {
        mach_vm_address_t search_address = (addr & ~(page_size_ - 1));
        mach_vm_address_t region = search_address;
        natural_t depth = 0;

        while (true)
        {
            mach_vm_size_t size = 0;
            vm_region_submap_short_info_data_64_t info{};
            mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;

            kern_return_t kr = mach_vm_region_recurse(task_,
                                                      &region,
                                                      &size,
                                                      &depth,
                                                      reinterpret_cast<vm_region_recurse_info_t>(&info),
                                                      &count);

            if (kr != KERN_SUCCESS)
                return false;

            if (info.is_submap)
            {
                ++depth;
                continue;
            }

            mach_vm_address_t region_end = region + size;
            if (region_end < region)
                return false;

            if (search_address < region || search_address >= region_end)
                return false;

            bool readable = (info.protection & VM_PROT_READ) != 0;
            bool writable = (info.protection & VM_PROT_WRITE) != 0;
            bool executable = (info.protection & VM_PROT_EXECUTE) != 0;

            if (info_out)
                *info_out = RegionInfo(region, region + size, readable, writable, executable);

            break;
        }

        return true;
    }

    if (!cachedRegions_.empty())
    {
        if (last_region_index_ < cachedRegions_.size() && cachedRegions_[last_region_index_].start <= addr &&
            addr < cachedRegions_[last_region_index_].end)
        {
            *info_out = cachedRegions_[last_region_index_];
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
            *info_out = cachedRegions_[best_match];
            return true;
        }
    }

    return false;
}

void KittyPtrValidator::refreshRegionCache()
{
    cachedRegions_.clear();
    mach_vm_address_t address = 0;
    natural_t depth = 0;

    while (true)
    {
        mach_vm_size_t size = 0;
        vm_region_submap_short_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task_,
                                                  &address,
                                                  &size,
                                                  &depth,
                                                  (vm_region_recurse_info_t)&info,
                                                  &count);

        if (kr != KERN_SUCCESS)
            break;

        // If the region points to a submap (nested page directory),
        // increment depth to step inside it without advancing the search address.
        if (info.is_submap)
        {
            depth++;
            continue;
        }

        mach_vm_address_t next = address + size;
        if (next <= address)
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

        address = next;
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
    addr = KittyUtils::untagPointer(addr);
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

    ptr = KittyUtils::untagPointer(ptr);

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

    ptr = KittyUtils::untagPointer(ptr);

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

    ptr = KittyUtils::untagPointer(ptr);

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