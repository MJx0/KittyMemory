#include "KittyMemory.hpp"

#ifdef __APPLE__
extern "C"
{
    kern_return_t mach_vm_protect(vm_map_t target_task,
                                  mach_vm_address_t address,
                                  mach_vm_size_t size,
                                  boolean_t set_maximum,
                                  vm_prot_t new_protection);

    kern_return_t mach_vm_write(vm_map_t target_task,
                                mach_vm_address_t address,
                                vm_offset_t data,
                                mach_msg_type_number_t dataCnt);

    kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task,
                                         mach_vm_address_t address,
                                         mach_vm_size_t size,
                                         mach_vm_address_t data,
                                         mach_vm_size_t *outsize);

    kern_return_t mach_vm_region_recurse(vm_map_read_t target_task,
                                         mach_vm_address_t *address,
                                         mach_vm_size_t *size,
                                         natural_t *nesting_depth,
                                         vm_region_recurse_info_t info,
                                         mach_msg_type_number_t *infoCnt);

    int proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize);

#define KT_PROC_PIDPATHINFO_MAXSIZE 4096
}
#endif

namespace KittyMemory
{

#ifdef __ANDROID__

    std::string getProcessName()
    {
        const char *file = "/proc/self/cmdline";
        char cmdline[128] = {0};
        FILE *fp = fopen(file, "r");
        if (!fp)
        {
            KITTY_LOGE("Couldn't open file %s.", file);
            return "";
        }
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        return cmdline;
    }

    std::vector<ProcMap> getAllMaps()
    {
        std::vector<ProcMap> retMaps;
        const char *file = "/proc/self/maps";
        char line[512] = {0};

        FILE *fp = fopen(file, "r");
        if (!fp)
        {
            KITTY_LOGE("Couldn't open file %s.", file);
            return retMaps;
        }

        while (fgets(line, sizeof(line), fp))
        {
            ProcMap map{};

            char perms[5] = {0}, dev[11] = {0}, pathname[256] = {0};
            // parse a line in maps file
            // (format) startAddress-endAddress perms offset dev inode pathname
            sscanf(line,
                   "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %s %" SCNu64 " %s",
                   &map.startAddress,
                   &map.endAddress,
                   perms,
                   &map.offset,
                   dev,
                   &map.inode,
                   pathname);

            map.length = map.endAddress - map.startAddress;
            map.dev = dev;
            map.pathname = pathname;

            if (perms[0] == 'r')
            {
                map.protection |= PROT_READ;
                map.readable = true;
            }
            if (perms[1] == 'w')
            {
                map.protection |= PROT_WRITE;
                map.writeable = true;
            }
            if (perms[2] == 'x')
            {
                map.protection |= PROT_EXEC;
                map.executable = true;
            }

            map.is_private = (perms[3] == 'p');
            map.is_shared = (perms[3] == 's');

            map.is_rx = (strncmp(perms, "r-x", 3) == 0);
            map.is_rw = (strncmp(perms, "rw-", 3) == 0);
            map.is_ro = (strncmp(perms, "r--", 3) == 0);

            retMaps.push_back(map);
        }

        fclose(fp);

        if (retMaps.empty())
        {
            KITTY_LOGE("getAllMaps err couldn't find any map");
        }
        else
        {
            std::sort(retMaps.begin(), retMaps.end(), [](const ProcMap &a, const ProcMap &b) {
                return a.startAddress < b.startAddress;
            });
        }

        return retMaps;
    }

    std::vector<ProcMap> getMaps(EProcMapFilter filter, const std::string &name, const std::vector<ProcMap> &maps)
    {
        std::vector<ProcMap> retMaps;
        regex_t re{};
        bool isRegex = (filter == EProcMapFilter::Regex);

        if (isRegex)
        {
            if (regcomp(&re, name.c_str(), REG_EXTENDED | REG_NOSUB) != 0)
                return retMaps;
        }

        for (const auto &it : maps)
        {
            if (!it.isValid())
                continue;

            bool match = false;
            switch (filter)
            {
            case EProcMapFilter::Equal:
                match = (it.pathname == name);
                break;
            case EProcMapFilter::StartWith:
                match = KittyUtils::String::startsWith(it.pathname, name);
                break;
            case EProcMapFilter::EndWith:
                match = KittyUtils::String::endsWith(it.pathname, name);
                break;
            case EProcMapFilter::Regex:
                match = (regexec(&re, it.pathname.c_str(), 0, NULL, 0) == 0);
                break;
            case EProcMapFilter::Contains:
            default:
                match = KittyUtils::String::contains(it.pathname, name);
                break;
            }

            if (match)
            {
                retMaps.push_back(it);
            }
        }

        if (isRegex)
            regfree(&re);

        return retMaps;
    }

    ProcMap getAddressMap(uintptr_t address, const std::vector<ProcMap> &maps)
    {
        if (!address)
            return {};

        uintptr_t p = KittyUtils::untagPointer(address);

        auto it = std::lower_bound(maps.begin(), maps.end(), p, [](const ProcMap &m, uintptr_t val) {
            return m.endAddress <= val;
        });

        if (it != maps.end() && p >= it->startAddress && p < it->endAddress)
        {
            return *it;
        }

        return {};
    }

    std::vector<std::vector<ProcMap>> getFileMappings(const std::string &path, const std::vector<ProcMap> &maps)
    {
        auto matched_maps = getMaps(EProcMapFilter::EndWith, path, maps);
        if (matched_maps.empty())
            return {};

        std::sort(matched_maps.begin(), matched_maps.end(), [](const auto &a, const auto &b) {
            return a.startAddress < b.startAddress;
        });

        std::vector<std::vector<ProcMap>> mappings;
        mappings.emplace_back();
        mappings.back().push_back(matched_maps.front());

        uint64_t expectedNextOffset = matched_maps.front().offset + matched_maps.front().length;

        for (size_t i = 1; i < matched_maps.size(); ++i)
        {
            const auto &prev = mappings.back().back();
            const auto &r = matched_maps[i];

            const bool contiguousVA = (r.startAddress == prev.endAddress);
            const bool contiguousFile = (r.offset == expectedNextOffset);

            if (contiguousVA && contiguousFile)
            {
                mappings.back().push_back(r);
                expectedNextOffset += r.length;
            }
            else
            {
                mappings.emplace_back();
                mappings.back().push_back(r);
                expectedNextOffset = r.offset + r.length;
            }
        }

        return mappings;
    }

    bool memProtect(uintptr_t address, size_t length, int protection)
    {
        uintptr_t pageStart = KT_PAGE_START(address);
        size_t pageLen = KT_PAGE_REMAIN2(address, length);
        int ret = KT_EINTR_RETRY(mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection));
        return ret == 0;
    }

    template <typename T>
    static bool memPatch(uintptr_t address, void *buffer, size_t len, int requiredProt, T &&operation)
    {
        if (!address || !buffer || !len)
            return false;

        uintptr_t current = address;
        uintptr_t end = address + len;

        if (end <= current)
            return false;

        while (current < end)
        {
            ProcMap map = getAddressMap(current);
            if (!map.isValid())
                return false;

            size_t chunk = std::min<size_t>(map.endAddress - current, end - current);

            int oldProt = map.protection;
            bool restoreProtection = false;
            bool permissionGranted = (oldProt & requiredProt);

            if (!permissionGranted)
            {
                int newProt = oldProt | requiredProt;
                if (memProtect(current, chunk, newProt))
                {
                    permissionGranted = true;
                    restoreProtection = true;
                }
            }

            bool ok = operation(current, buffer, chunk, permissionGranted);

            if (restoreProtection)
            {
                int restoreProt = oldProt;
                if (requiredProt & PROT_EXEC)
                    restoreProt |= PROT_EXEC;

                memProtect(current, chunk, restoreProt);
            }

            if (!ok)
                return false;

            if (permissionGranted && (requiredProt & PROT_WRITE) &&
                ((oldProt & PROT_EXEC) || (requiredProt & PROT_EXEC)))
            {
                __builtin___clear_cache((char *)current, (char *)current + chunk);
            }

            current += chunk;
            buffer = static_cast<uint8_t *>(buffer) + chunk;
        }

        return true;
    }

    bool memRead(uintptr_t address, void *buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", (void *)address, buffer, len);

        if (!address || !buffer || !len)
            return false;

        return memPatch(address,
                        buffer,
                        len,
                        PROT_READ,
                        [](uintptr_t addr, void *buf, size_t size, bool permissionGranted) -> bool {
                            if (!permissionGranted)
                                return false;
                            return memcpy(buf, reinterpret_cast<void *>(addr), size);
                        });
    }

    bool memWrite(uintptr_t address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memWrite(%p, %p, %zu)", (void *)address, buffer, len);

        if (!address || !buffer || !len)
            return false;

        return memPatch(address,
                        const_cast<void *>(buffer),
                        len,
                        PROT_WRITE,
                        [](uintptr_t addr, void *buf, size_t size, bool permissionGranted) -> bool {
                            if (!permissionGranted)
                                return false;
                            return memcpy(reinterpret_cast<void *>(addr), buf, size);
                        });
    }

    bool memExecWrite(uintptr_t address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memExecWrite(%p, %p, %zu)", (void *)address, buffer, len);

        if (!address || !buffer || !len)
            return false;

        return memPatch(address,
                        const_cast<void *>(buffer),
                        len,
                        PROT_WRITE | PROT_EXEC,
                        [](uintptr_t addr, void *buf, size_t size, bool permissionGranted) -> bool {
                            if (!permissionGranted)
                                return false;
                            return memcpy(reinterpret_cast<void *>(addr), buf, size);
                        });
    }

    bool dumpMemToDisk(uintptr_t address, size_t size, const std::string &destination, const std::vector<ProcMap> &maps)
    {
        if (!address || !size || destination.empty() || maps.empty())
            return false;

        address = KittyUtils::untagPointer(address);
        uintptr_t endAddress = address + size;
        if (endAddress < address)
            return false;

        KittyIOFile dest(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (!dest.open())
            return false;

        std::vector<char> zeroBuffer(0x10000, 0);
        auto fillZeros = [&](size_t count) -> bool {
            while (count)
            {
                size_t chunk = std::min(count, zeroBuffer.size());
                ssize_t written = dest.write(zeroBuffer.data(), chunk);
                if (written != (ssize_t)chunk)
                    return false;

                count -= chunk;
            }

            return true;
        };

        uintptr_t current = address;

        for (const auto &map : maps)
        {
            if (map.endAddress <= current)
                continue;

            if (map.startAddress >= endAddress)
                break;

            /*
             * Hole between mappings.
             */
            if (map.startAddress > current)
            {
                size_t hole = map.startAddress - current;

                if (!fillZeros(hole))
                {
                    dest.close();
                    return false;
                }

                current = map.startAddress;
            }

            uintptr_t dumpStart = std::max(current, map.startAddress);
            uintptr_t dumpEnd = std::min(endAddress, map.endAddress);
            size_t dumpSize = dumpEnd - dumpStart;

            if (!dumpSize)
                continue;

            bool restoreProtection = false;
            uintptr_t protectStart = 0;
            size_t protectSize = 0;

            /*
             * Add read permission when needed.
             */
            if (!map.readable)
            {
                protectStart = KT_PAGE_START(dumpStart);
                uintptr_t protectEnd = KT_PAGE_END(dumpEnd);
                protectSize = protectEnd - protectStart;
                if (mprotect(reinterpret_cast<void *>(protectStart), protectSize, map.protection | PROT_READ) == 0)
                {
                    restoreProtection = true;
                }
            }

            size_t copiedBytes = 0;

            if (map.readable || restoreProtection)
            {
                ssize_t written = dest.write(reinterpret_cast<void *>(dumpStart), dumpSize);

                if (written > 0)
                    copiedBytes = static_cast<size_t>(written);
            }

            /*
             * Restore original protection.
             */
            if (restoreProtection)
            {
                mprotect(reinterpret_cast<void *>(protectStart), protectSize, map.protection);
            }

            /*
             * Preserve offsets for failed/partial ranges.
             */
            if (copiedBytes < dumpSize)
            {
                if (!fillZeros(dumpSize - copiedBytes))
                {
                    dest.close();
                    return false;
                }
            }

            current = dumpEnd;
        }

        /*
         * Tail after the last mapping.
         */
        if (current < endAddress)
        {
            if (!fillZeros(endAddress - current))
            {
                dest.close();
                return false;
            }

            current = endAddress;
        }

        dest.close();

        return current == endAddress;
    }

    bool dumpFileMappingsToDisk(const std::string &memFile,
                                const std::string &destination,
                                const std::vector<ProcMap> &maps)
    {
        if (memFile.empty() || destination.empty() || maps.empty())
            return false;

        auto fileMappings = getFileMappings(memFile, maps);
        if (fileMappings.empty())
            return false;

        std::string outPath = destination;
        kt_stat64_t st{};

        if (kt_stat64(destination.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
        {
            // Destination is an existing directory.
            if (access(destination.c_str(), W_OK) != 0)
                return false;

            size_t pos = memFile.find_last_of("/\\");
            outPath += (outPath[outPath.length() - 1] == '/' || outPath[outPath.length() - 1] == '\\') ? "" : "/";
            outPath += (pos == std::string::npos) ? memFile : memFile.substr(pos + 1);
        }
        else
        {
            // Destination is a file path.
            if (kt_stat64(outPath.c_str(), &st) == 0)
            {
                // Existing file: must be writable.
                if (access(outPath.c_str(), W_OK) != 0)
                    return false;
            }
            else
            {
                // New file: parent directory must be writable.
                size_t pos = outPath.find_last_of("/\\");
                std::string parent = (pos == std::string::npos) ? "." : outPath.substr(0, pos);

                if (access(parent.c_str(), W_OK) != 0)
                    return false;
            }
        }

        bool dumpedAtleastOne = false;

        for (size_t i = 0; i < fileMappings.size(); ++i)
        {
            std::string filePath = outPath;

            if (fileMappings.size() > 1)
            {
                size_t dot = filePath.find_last_of('.');
                if (dot != std::string::npos)
                    filePath.insert(dot, "_" + std::to_string(i));
                else
                    filePath += "_" + std::to_string(i);
            }

            uintptr_t start = fileMappings[i].front().startAddress;
            uintptr_t end = fileMappings[i].back().endAddress;

            if (dumpMemToDisk(start, end - start, filePath, maps))
                dumpedAtleastOne = true;
        }

        return dumpedAtleastOne;
    }


#if defined(__aarch64__)
#define syscall_rpmv_n 270
#define syscall_wpmv_n 271
#elif defined(__arm__)
#define syscall_rpmv_n 376
#define syscall_wpmv_n 377
#elif defined(__i386__)
#define syscall_rpmv_n 347
#define syscall_wpmv_n 348
#elif defined(__x86_64__)
#define syscall_rpmv_n 310
#define syscall_wpmv_n 311
#else
#error "Unsupported ABI"
#endif

    static ssize_t syscall_process_vm_readv(pid_t pid,
                                            const iovec *lvec,
                                            unsigned long liovcnt,
                                            const iovec *rvec,
                                            unsigned long riovcnt,
                                            unsigned long flags)
    {
        return syscall(syscall_rpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
    }

    static ssize_t syscall_process_vm_writev(pid_t pid,
                                             const iovec *lvec,
                                             unsigned long liovcnt,
                                             const iovec *rvec,
                                             unsigned long riovcnt,
                                             unsigned long flags)
    {
        return syscall(syscall_wpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
    }

#elif __APPLE__

    std::vector<mem_range_info_t> getAllRegions()
    {
        std::vector<mem_range_info_t> regions;

        mach_vm_address_t address = 0;
        natural_t depth = 0;

        while (true)
        {
            mach_vm_size_t size = 0;
            vm_region_submap_short_info_data_64_t info{};
            mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
            kern_return_t kr = mach_vm_region_recurse(mach_task_self(),
                                                      &address,
                                                      &size,
                                                      &depth,
                                                      reinterpret_cast<vm_region_recurse_info_t>(&info),
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

            mem_range_info_t region{};
            region.start = static_cast<uintptr_t>(address);
            region.size = static_cast<size_t>(size);
            region.end = region.start + region.size;
            region.offset = info.offset;

            region.readable = (info.protection & VM_PROT_READ) != 0;
            region.writeable = (info.protection & VM_PROT_WRITE) != 0;
            region.executable = (info.protection & VM_PROT_EXECUTE) != 0;

            region.protection = info.protection;
            region.max_protection = info.max_protection;

            char path[KT_PROC_PIDPATHINFO_MAXSIZE] = {};
            int ret = proc_regionfilename(getpid(), static_cast<uint64_t>(address), path, sizeof(path));
            if (ret > 0)
            {
                region.name.assign(path, static_cast<size_t>(ret));
            }

            regions.push_back(region);

            address = next;
        }

        if (!regions.empty())
        {
            std::sort(regions.begin(), regions.end(), [](const mem_range_info_t &a, const mem_range_info_t &b) {
                return a.start < b.start;
            });
        }

        return regions;
    }

    std::vector<mem_range_info_t> getRegions(EMemRegionFilter filter,
                                             const std::string &name,
                                             const std::vector<mem_range_info_t> &regions)

    {
        std::vector<mem_range_info_t> retRegions;
        regex_t re{};
        bool isRegex = (filter == EMemRegionFilter::Regex);

        if (isRegex)
        {
            if (regcomp(&re, name.c_str(), REG_EXTENDED | REG_NOSUB) != 0)
                return retRegions;
        }

        for (const auto &it : regions)
        {
            if (!it.isValid())
                continue;

            bool match = false;
            switch (filter)
            {
            case EMemRegionFilter::Equal:
                match = (it.name == name);
                break;
            case EMemRegionFilter::StartWith:
                match = KittyUtils::String::startsWith(it.name, name);
                break;
            case EMemRegionFilter::EndWith:
                match = KittyUtils::String::endsWith(it.name, name);
                break;
            case EMemRegionFilter::Regex:
                match = (regexec(&re, it.name.c_str(), 0, NULL, 0) == 0);
                break;
            case EMemRegionFilter::Contains:
            default:
                match = KittyUtils::String::contains(it.name, name);
                break;
            }

            if (match)
            {
                retRegions.push_back(it);
            }
        }

        if (isRegex)
            regfree(&re);

        return retRegions;
    }

    mem_range_info_t getAddressRegion(mach_vm_address_t address, const std::vector<mem_range_info_t> &regions)
    {
        if (!address)
            return {};

        auto it = std::lower_bound(regions.begin(),
                                   regions.end(),
                                   address,
                                   [](const mem_range_info_t &m, uintptr_t val) { return m.end <= val; });

        if (it != regions.end() && address >= it->start && address < it->end)
        {
            return *it;
        }

        return {};
    }

    std::vector<std::vector<mem_range_info_t>> getFileMappings(const std::string &path,
                                                               const std::vector<mem_range_info_t> &regions)
    {
        auto matched_regions = getRegions(EMemRegionFilter::EndWith, path, regions);
        if (matched_regions.empty())
            return {};

        std::sort(matched_regions.begin(), matched_regions.end(), [](const auto &a, const auto &b) {
            return a.start < b.start;
        });

        std::vector<std::vector<mem_range_info_t>> mappings;
        mappings.emplace_back();
        mappings.back().push_back(matched_regions.front());

        uint64_t expectedNextOffset = matched_regions.front().offset + matched_regions.front().size;

        for (size_t i = 1; i < matched_regions.size(); ++i)
        {
            const auto &prev = mappings.back().back();
            const auto &r = matched_regions[i];

            const bool contiguousVA = (r.start == prev.end);
            const bool contiguousFile = (r.offset == expectedNextOffset);

            if (contiguousVA && contiguousFile)
            {
                mappings.back().push_back(r);
                expectedNextOffset += r.size;
            }
            else
            {
                mappings.emplace_back();
                mappings.back().push_back(r);
                expectedNextOffset = r.offset + r.size;
            }
        }

        return mappings;
    }

    uintptr_t getAbsoluteAddress(const char *imageName, uintptr_t address)
    {
        const uint32_t imageCount = _dyld_image_count();

        if (!imageName)
        {
            uint32_t exeBufSize = 1024;
            std::vector<char> exeBuf(exeBufSize, 0);
            if (_NSGetExecutablePath(exeBuf.data(), &exeBufSize) == -1)
            {
                exeBuf.clear();
                exeBuf.resize(exeBufSize + 1, 0);
                _NSGetExecutablePath(exeBuf.data(), &exeBufSize);
            }

            int exeIdx = -1;
            for (uint32_t i = 0; i < imageCount; i++)
            {
                const mach_header *hdr = _dyld_get_image_header(i);
                if (!hdr || hdr->filetype != MH_EXECUTE)
                    continue;

                if (exeIdx == -1)
                    exeIdx = i;

                const char *name = _dyld_get_image_name(i);
                if (!name || strcmp(name, exeBuf.data()) != 0)
                    continue;

                exeIdx = i;
                break;
            }

            if (exeIdx < 0)
                return 0;

            return address + _dyld_get_image_vmaddr_slide(exeIdx);
        }
        else
        {
            for (uint32_t i = 0; i < imageCount; i++)
            {
                const char *name = _dyld_get_image_name(i);
                if (!name)
                    continue;

                if (!KittyUtils::String::endsWith(std::string(name), imageName))
                    continue;

                return address + _dyld_get_image_vmaddr_slide(i);
            }
        }

        return 0;
    }

    bool memProtect(uintptr_t address, size_t length, vm_prot_t protection)
    {
        uintptr_t pageStart = KT_PAGE_START(address);
        size_t pageLen = KT_PAGE_REMAIN2(address, length);
        kern_return_t ret = mach_vm_protect(mach_task_self(), pageStart, pageLen, false, protection);
        return ret == KERN_SUCCESS;
    }

    template <typename T>
    static bool memPatch(uintptr_t address, void *buffer, size_t len, vm_prot_t requiredProt, T &&operation)
    {
        if (!address || !buffer || !len)
            return false;

        uintptr_t current = address;
        uintptr_t end = address + len;

        if (end <= current)
            return false;

        while (current < end)
        {
            mem_range_info_t info = getAddressRegion(current);
            if (!info.isValid())
                return false;

            uintptr_t regionEnd = std::min<uintptr_t>(info.end, end);
            size_t chunk = regionEnd - current;

            vm_prot_t oldProt = info.protection;
            bool restoreProtection = false;
            bool permissionGranted = (oldProt & requiredProt);

            if (!permissionGranted)
            {
                vm_prot_t newProt = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
                if (memProtect(current, chunk, newProt))
                {
                    permissionGranted = true;
                    restoreProtection = true;
                }
            }

            bool ok = operation(current, buffer, chunk, permissionGranted);

            if (restoreProtection)
            {
                memProtect(current, chunk, oldProt);
            }

            if (!ok)
                return false;

            if (permissionGranted && (requiredProt & VM_PROT_WRITE) &&
                ((oldProt & VM_PROT_EXECUTE) || (requiredProt & VM_PROT_EXECUTE)))
            {
                sys_icache_invalidate(reinterpret_cast<void *>(current), chunk);
            }

            current += chunk;
            buffer = static_cast<uint8_t *>(buffer) + chunk;
        }

        return true;
    }

    bool memRead(uintptr_t address, void *buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", (void *)address, buffer, len);

        if (!address || !buffer || !len)
            return false;

        return memPatch(address,
                        buffer,
                        len,
                        VM_PROT_READ,
                        [](uintptr_t addr, void *buf, size_t size, bool permissionGranted) -> bool {
                            if (!permissionGranted)
                                return false;
                            return memcpy(buf, reinterpret_cast<void *>(addr), size);
                        });
    }

    bool memWrite(uintptr_t address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memWrite(%p, %p, %zu)", (void *)address, buffer, len);

        if (!address || !buffer || !len)
            return false;

        return memPatch(address,
                        const_cast<void *>(buffer),
                        len,
                        VM_PROT_WRITE,
                        [](uintptr_t addr, void *buf, size_t size, bool permissionGranted) -> bool {
                            if (!permissionGranted)
                                return false;
                            return memcpy(reinterpret_cast<void *>(addr), buf, size);
                        });
    }

    bool dumpMemToDisk(uintptr_t address,
                       size_t size,
                       const std::string &destination,
                       const std::vector<mem_range_info_t> &regions)
    {
        if (!address || !size || destination.empty() || regions.empty())
            return false;

        uintptr_t endAddress = address + size;
        if (endAddress < address)
            return false;

        KittyIOFile dest(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (!dest.open())
            return false;

        std::vector<char> zeroBuffer(0x10000, 0);
        auto fillZeros = [&](size_t count) -> bool {
            while (count)
            {
                size_t chunk = std::min(count, zeroBuffer.size());
                ssize_t written = dest.write(zeroBuffer.data(), chunk);
                if (written != (ssize_t)chunk)
                    return false;

                count -= chunk;
            }

            return true;
        };

        uintptr_t current = address;

        for (const auto &region : regions)
        {
            if (region.end <= current)
                continue;

            if (region.start >= endAddress)
                break;

            /*
             * Hole between mappings.
             */
            if (region.start > current)
            {
                size_t hole = region.start - current;

                if (!fillZeros(hole))
                {
                    dest.close();
                    return false;
                }

                current = region.start;
            }

            uintptr_t dumpStart = std::max(current, region.start);
            uintptr_t dumpEnd = std::min(endAddress, region.end);
            size_t dumpSize = dumpEnd - dumpStart;

            if (!dumpSize)
                continue;

            bool restoreProtection = false;
            uintptr_t protectStart = 0;
            size_t protectSize = 0;

            /*
             * Add read permission when needed.
             */
            if (!region.readable)
            {
                protectStart = KT_PAGE_START(dumpStart);
                uintptr_t protectEnd = KT_PAGE_END(dumpEnd);
                protectSize = protectEnd - protectStart;
                if (mach_vm_protect(mach_task_self(),
                                    protectStart,
                                    protectSize,
                                    false,
                                    region.protection | VM_PROT_READ) == KERN_SUCCESS)
                {
                    restoreProtection = true;
                }
            }

            size_t copiedBytes = 0;

            if (region.readable || restoreProtection)
            {
                ssize_t written = dest.write(reinterpret_cast<void *>(dumpStart), dumpSize);

                if (written > 0)
                    copiedBytes = static_cast<size_t>(written);
            }

            /*
             * Restore original protection.
             */
            if (restoreProtection)
            {
                mach_vm_protect(mach_task_self(), protectStart, protectSize, false, region.protection);
            }

            /*
             * Preserve offsets for failed/partial ranges.
             */
            if (copiedBytes < dumpSize)
            {
                if (!fillZeros(dumpSize - copiedBytes))
                {
                    dest.close();
                    return false;
                }
            }

            current = dumpEnd;
        }

        /*
         * Tail after the last mapping.
         */
        if (current < endAddress)
        {
            if (!fillZeros(endAddress - current))
            {
                dest.close();
                return false;
            }

            current = endAddress;
        }

        dest.close();

        return current == endAddress;
    }

    bool dumpFileMappingsToDisk(const std::string &memFile,
                                const std::string &destination,
                                const std::vector<mem_range_info_t> &regions)
    {
        if (memFile.empty() || destination.empty() || regions.empty())
            return false;

        auto fileMappings = getFileMappings(memFile, regions);
        if (fileMappings.empty())
            return false;

        std::string outPath = destination;
        kt_stat64_t st{};

        if (kt_stat64(destination.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
        {
            // Destination is an existing directory.
            if (access(destination.c_str(), W_OK) != 0)
                return false;

            size_t pos = memFile.find_last_of("/\\");
            outPath += (outPath[outPath.length() - 1] == '/' || outPath[outPath.length() - 1] == '\\') ? "" : "/";
            outPath += (pos == std::string::npos) ? memFile : memFile.substr(pos + 1);
        }
        else
        {
            // Destination is a file path.
            if (kt_stat64(outPath.c_str(), &st) == 0)
            {
                // Existing file: must be writable.
                if (access(outPath.c_str(), W_OK) != 0)
                    return false;
            }
            else
            {
                // New file: parent directory must be writable.
                size_t pos = outPath.find_last_of("/\\");
                std::string parent = (pos == std::string::npos) ? "." : outPath.substr(0, pos);

                if (access(parent.c_str(), W_OK) != 0)
                    return false;
            }
        }

        bool dumpedAtleastOne = false;

        for (size_t i = 0; i < fileMappings.size(); ++i)
        {
            std::string filePath = outPath;

            if (fileMappings.size() > 1)
            {
                size_t dot = filePath.find_last_of('.');
                if (dot != std::string::npos)
                    filePath.insert(dot, "_" + std::to_string(i));
                else
                    filePath += "_" + std::to_string(i);
            }

            uintptr_t start = fileMappings[i].front().start;
            uintptr_t end = fileMappings[i].back().end;

            if (dumpMemToDisk(start, end - start, filePath, regions))
                dumpedAtleastOne = true;
        }

        return dumpedAtleastOne;
    }


#endif // __APPLE__

    /**
     * @brief Amount of contiguous successfully processed memory before retrying
     *        a large continuous transfer.
     *
     * After entering page mode, once this amount of memory has been successfully
     * processed, the operation attempts to return to normal large-range mode.
     */
    static constexpr size_t KT_RETRY_NORMAL_AFTER = 64 * 1024;

    /**
     * @brief Internal transfer state.
     *
     * Used by KittyMemoryTransfer() to switch between continuous transfers and
     * page-by-page transfers.
     */
    enum class KTTransferState
    {
        /**
         * @brief Attempt to process the entire remaining region.
         */
        Normal,


        /**
         * @brief Process memory one page at a time.
         */
        Page
    };

    /**
     * @brief Performs a memory transfer with optional inaccessible-page handling.
     *
     * This helper implements the common logic shared by memory operations backends.
     *
     * Behavior:
     *
     * - MemMode::Normal:
     *   Performs a single continuous transfer attempt.
     *
     * - MemMode::SkipInaccessiblePages:
     *   Attempts a continuous transfer first. If it fails, switches to page mode
     *   and skips inaccessible pages. After 64 KiB of contiguous successful
     *   transfers, it retries continuous mode.
     *
     * @tparam T Callable type implementing the actual read/write operation.
     *
     * @param address Starting memory address.
     * @param buffer Buffer used for the transfer.
     * @param len Number of bytes to transfer.
     * @param mode Transfer behavior.
     * @param operation Backend memory operation callback.
     *
     * @return Number of bytes successfully transferred.
     */
    template <typename T>
    static size_t KittyMemoryTransfer(uintptr_t address, void *buffer, size_t len, MemMode mode, T &&operation)
    {
        if (!address || !buffer || !len)
            return 0;

        size_t total = 0;

        KTTransferState state = KTTransferState::Normal;

        size_t contiguousSuccess = 0;

        while (len)
        {
            size_t requestSize = len;

            if (state == KTTransferState::Page)
                requestSize = std::min(KT_PAGE_REMAIN(address), len);

            ssize_t sn = static_cast<ssize_t>(operation(address, buffer, requestSize));
            if (sn < 0)
            {
#ifdef __APPLE__
                switch (sn)
                {
                case -KERN_INVALID_TASK:       // process exited
                case -KERN_RESOURCE_SHORTAGE:  // kernel could not allocate resources
                case -KERN_PROTECTION_FAILURE: // permission lost
                case -KERN_INVALID_ARGUMENT:   // invalid arguments
                    return total;
                default:
                    break;
                }
#else
                switch (sn)
                {
                case -ESRCH:  // process exited
                case -EBADF:  // invalid fd
                case -EPERM:  // permission lost
                case -EINVAL: // invalid arguments
                    return total;
                default:
                    break;
                }
#endif
            }

            size_t n = sn < 0 ? 0 : static_cast<size_t>(sn);

            if (n > 0)
            {
                total += n;

                address += n;
                buffer = static_cast<char *>(buffer) + n;
                len -= n;

                if (state == KTTransferState::Page)
                {
                    contiguousSuccess += n;

                    if (contiguousSuccess >= KT_RETRY_NORMAL_AFTER)
                    {
                        state = KTTransferState::Normal;
                        contiguousSuccess = 0;
                    }
                }

                // partial success means remaining bytes are still pending
                if (n != requestSize && mode == MemMode::Normal)
                {
                    break;
                }

                continue;
            }

            /*
             * No bytes transferred.
             */

            if (mode == MemMode::Normal)
                break;

            if (state == KTTransferState::Normal)
            {
                /*
                 * Large request failed.
                 * Switch to page scanning.
                 */
                state = KTTransferState::Page;
                contiguousSuccess = 0;
                continue;
            }

            /*
             * Page failed.
             * Skip it.
             */
            size_t skip = std::min(KT_PAGE_REMAIN(address), len);

            address += skip;
            buffer = static_cast<char *>(buffer) + skip;
            len -= skip;

            contiguousSuccess = 0;
        }

        return total;
    }

#ifdef __APPLE__

    size_t syscallMemRead(uintptr_t address, void *buffer, size_t len, MemMode mode)
    {
        return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
            mach_vm_size_t outSize = 0;
            kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                                      static_cast<mach_vm_address_t>(addr),
                                                      static_cast<mach_vm_size_t>(size),
                                                      reinterpret_cast<mach_vm_address_t>(buf),
                                                      &outSize);
            return kr != KERN_SUCCESS ? static_cast<ssize_t>(-kr) : static_cast<ssize_t>(outSize);
        });
    }

    size_t syscallMemWrite(uintptr_t address, void *buffer, size_t len, MemMode mode)
    {
        return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
            kern_return_t kr = mach_vm_write(mach_task_self(),
                                             static_cast<mach_vm_address_t>(addr),
                                             reinterpret_cast<vm_offset_t>(buf),
                                             static_cast<mach_msg_type_number_t>(size));
            return kr != KERN_SUCCESS ? static_cast<ssize_t>(-kr) : static_cast<ssize_t>(size);
        });
    }

#else

    size_t syscallMemRead(uintptr_t address, void *buffer, size_t len, MemMode mode)
    {
        address = KittyUtils::untagPointer(address);

        return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
            errno = 0;
            struct iovec local{buf, size};
            struct iovec remote{reinterpret_cast<void *>(addr), size};
            ssize_t n = KT_EINTR_RETRY(syscall_process_vm_readv(getpid(), &local, 1, &remote, 1, 0));
            return n < 0 ? static_cast<ssize_t>(-errno) : static_cast<ssize_t>(n);
        });
    }

    size_t syscallMemWrite(uintptr_t address, void *buffer, size_t len, MemMode mode)
    {
        address = KittyUtils::untagPointer(address);
        
        return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
            errno = 0;
            struct iovec local{buf, size};
            struct iovec remote{reinterpret_cast<void *>(addr), size};
            ssize_t n = KT_EINTR_RETRY(syscall_process_vm_writev(getpid(), &local, 1, &remote, 1, 0));
            return n < 0 ? static_cast<ssize_t>(-errno) : static_cast<ssize_t>(n);
        });
    }

#endif

} // namespace KittyMemory
