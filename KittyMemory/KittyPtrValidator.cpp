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
        kern_return_t kret = vm_region_recurse_64(task_, &address, &size, &nesting_depth,
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
        if (last_region_index_ < cachedRegions_.size() &&
            cachedRegions_[last_region_index_].start <= addr &&
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

        if (best_match < cachedRegions_.size() &&
            cachedRegions_[best_match].start <= addr &&
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
        kern_return_t kret = vm_region_recurse_64(task_, &address, &size, &nesting_depth,
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
        std::sort(
            cachedRegions_.begin(), cachedRegions_.end(),
            [](const RegionInfo &a, const RegionInfo &b) { return a.start < b.start; });
    }

    last_region_index_ = 0;
}

#else

std::string KittyPtrValidator::_readMapsFile()
{
    std::string buffer;

    char filePath[256] = {0};
    snprintf(filePath, sizeof(filePath), "/proc/%d/maps", pid_);

    int fd = open(filePath, O_RDONLY);
    if (fd < 0)
        return buffer;

    char tmp_buf[4096] = {0};
    ssize_t n = 0, off = 0;
    while ((n = pread64(fd, tmp_buf, 4096, off)) > 0)
    {
        buffer.append(tmp_buf, n);
        off += n;
    }

    close(fd);

    return buffer;
}

bool KittyPtrValidator::_parseMapsLine(const std::string &line, RegionInfo *region)
{
    if (line.empty())
        return false;

    uintptr_t start, end;
    char perms[5] = {0};
    int parsed = sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, perms);
    if (parsed != 3)
        return false;

    *region = RegionInfo(start, end, perms[0] == 'r', perms[1] == 'w', perms[2] == 'x');
    return true;
}

void KittyPtrValidator::_parseMapsFromBuffer(const std::string &buffer,
                                             std::vector<RegionInfo> *output)
{
    if (!output)
        return;

    output->clear();
    size_t pos = 0;
    while (pos < buffer.size())
    {
        size_t end = buffer.find('\n', pos);
        if (end == std::string::npos)
        {
            end = buffer.size();
        }

        std::string line(buffer.data() + pos, end - pos);
        pos = end + 1;

        RegionInfo new_region(0, 0, false, false, false);
        if (!_parseMapsLine(line, &new_region))
            continue;

        if (!output->empty() && output->back().canMergeWith(new_region))
        {
            output->back().end = new_region.end;
        }
        else
        {
            output->emplace_back(new_region);
        }
    }

    if (!output->empty())
    {
        std::sort(
            output->begin(), output->end(),
            [](const RegionInfo &a, const RegionInfo &b) { return a.start < b.start; });
    }
}

bool KittyPtrValidator::_findRegion(uintptr_t addr, RegionInfo *region)
{
    if (!use_cache_)
    {
        std::string maps_data = _readMapsFile();
        if (maps_data.empty())
            return false;

        size_t pos = 0;
        while (pos < maps_data.size())
        {
            size_t end = maps_data.find('\n', pos);
            if (end == std::string::npos)
            {
                end = maps_data.size();
            }

            std::string line(maps_data.data() + pos, end - pos);
            pos = end + 1;

            RegionInfo new_region(0, 0, false, false, false);
            if (!_parseMapsLine(line, &new_region))
                continue;

            *region = new_region;
            return (new_region.start <= addr && addr < new_region.end);
        }
        return false;
    }

    if (!cachedRegions_.empty())
    {
        if (last_region_index_ < cachedRegions_.size() &&
            cachedRegions_[last_region_index_].start <= addr &&
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

        if (best_match < cachedRegions_.size() &&
            cachedRegions_[best_match].start <= addr &&
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
    std::string maps_data = _readMapsFile();
    if (maps_data.empty())
        return;

    _parseMapsFromBuffer(maps_data, &cachedRegions_);
    last_region_index_ = 0;
}

#endif
