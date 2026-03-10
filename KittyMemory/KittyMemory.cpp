#include "KittyMemory.hpp"

#ifdef __APPLE__
#if 0
bool findMSHookMemory(void *dst, const void *src, size_t len);
#endif
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
}
#endif

namespace KittyMemory
{

#ifdef __ANDROID__

    int memProtect(const void *address, size_t length, int protection)
    {
        uintptr_t pageStart = KT_PAGE_START(address);
        size_t pageLen = KT_PAGE_LEN2(address, length);
        int ret = mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection);
        KITTY_LOGD("%s", getAddressMap(pageStart).toString().c_str());
        return ret;
    }

    bool memRead(const void *address, void *buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", address, buffer, len);

        if (!address)
        {
            KITTY_LOGE("memRead err address (%p) is null", address);
            return false;
        }

        if (!buffer)
        {
            KITTY_LOGE("memRead err buffer (%p) is null", buffer);
            return false;
        }

        if (!len)
        {
            KITTY_LOGE("memRead err invalid len");
            return false;
        }

        ProcMap addressMap = getAddressMap(address);
        if (!addressMap.isValid())
        {
            KITTY_LOGE("memRead err couldn't find address (%p) in any map", address);
            return false;
        }

        if (addressMap.protection & PROT_READ)
        {
            memcpy(buffer, address, len);
            return true;
        }

        if (memProtect(address, len, addressMap.protection | PROT_READ) != 0)
        {
            KITTY_LOGE("memRead err couldn't add write perm to address (%p, len: %zu, prot: %d)",
                       address,
                       len,
                       addressMap.protection);
            return false;
        }

        memcpy(buffer, address, len);

        if (memProtect(address, len, addressMap.protection) != 0)
        {
            KITTY_LOGE("memRead err couldn't revert protection of address (%p, len: %zu, prot: %d)",
                       address,
                       len,
                       addressMap.protection);
            return false;
        }

        return true;
    }

    bool memWrite(void *address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memWrite(%p, %p, %zu)", address, buffer, len);

        if (!address)
        {
            KITTY_LOGE("memWrite err address (%p) is null", address);
            return false;
        }

        if (!buffer)
        {
            KITTY_LOGE("memWrite err buffer (%p) is null", buffer);
            return false;
        }

        if (!len)
        {
            KITTY_LOGE("memWrite err invalid len");
            return false;
        }

        ProcMap addressMap = getAddressMap(address);
        if (!addressMap.isValid())
        {
            KITTY_LOGE("memWrite err couldn't find address (%p) in any map", address);
            return false;
        }

        if (addressMap.protection & PROT_WRITE)
        {
            memcpy(address, buffer, len);
            return true;
        }

        if (memProtect(address, len, KT_PROT_RWX) != 0)
        {
            KITTY_LOGE("memWrite err couldn't add write perm to address (%p, len: %zu, prot: %d)",
                       address,
                       len,
                       KT_PROT_RWX);
            return false;
        }

        memcpy(address, buffer, len);

        if (memProtect(address, len, KT_PROT_RX) != 0)
        {
            KITTY_LOGE("memWrite err couldn't revert protection of address (%p, len: %zu, prot: %d)",
                       address,
                       len,
                       KT_PROT_RX);
            return false;
        }

        return true;
    }

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
                   "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %s %lu %s",
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
            std::sort(retMaps.begin(), retMaps.end(), [](const KittyMemory::ProcMap &a, const KittyMemory::ProcMap &b) {
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

    ProcMap getAddressMap(const void *address, const std::vector<ProcMap> &maps)
    {
        if (!address)
            return {};

        uintptr_t p = KittyUtils::untagHeepPtr(uintptr_t(address));

        auto it = std::lower_bound(maps.begin(), maps.end(), p, [](const ProcMap &m, uintptr_t val) {
            return m.endAddress <= val;
        });

        if (it != maps.end() && p >= it->startAddress && p < it->endAddress)
        {
            return *it;
        }

        return {};
    }

    bool dumpMemToDisk(uintptr_t address, size_t size, const std::string &destination)
    {
        if (!address || !size || destination.empty())
            return false;

        address = KittyUtils::untagHeepPtr(address);
        uintptr_t endAddress = address + size;
        auto allMaps = getAllMaps();

        KittyIOFile dest(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (!dest.open())
            return false;

        uintptr_t currentPos = address;

        std::vector<char> zeroBuf;
        auto fillWithZeros = [&](size_t count) {
            if (count == 0)
                return;
            if (zeroBuf.size() < count)
                zeroBuf.resize(count, 0);
            dest.write(zeroBuf.data(), count);
        };

        for (const auto &it : allMaps)
        {
            if (it.endAddress <= currentPos)
                continue;

            if (it.startAddress >= endAddress)
                break;

            if (it.startAddress > currentPos)
            {
                fillWithZeros(it.startAddress - currentPos);
                currentPos = it.startAddress;
            }

            uintptr_t intersectStart = std::max(it.startAddress, currentPos);
            uintptr_t intersectEnd = std::min(it.endAddress, endAddress);
            size_t intersectSize = intersectEnd - intersectStart;

            bool success = false;
            bool changedPerms = false;

            if (!it.readable)
            {
                if (KittyMemory::memProtect((void *)it.startAddress, it.length, it.protection | PROT_READ) == 0)
                {
                    changedPerms = true;
                }
            }

            ssize_t nbytes = 0;
            if (it.readable || changedPerms)
            {
                nbytes = dest.write((const void *)intersectStart, intersectSize);
                if (nbytes == (ssize_t)intersectSize)
                {
                    success = true;
                }
            }

            if (!success)
            {
                fillWithZeros(intersectSize - nbytes);
            }

            if (changedPerms)
            {
                KittyMemory::memProtect((void *)it.startAddress, it.length, it.protection);
            }

            currentPos += intersectSize;
        }

        if (currentPos < endAddress)
        {
            fillWithZeros(endAddress - currentPos);
            currentPos = endAddress;
        }

        dest.close();
        return (currentPos - address) == size;
    }

    bool dumpMemFileToDisk(const std::string &memFile, const std::string &destination)
    {
        if (memFile.empty() || destination.empty())
            return false;

        auto fileMaps = KittyMemory::getMaps(EProcMapFilter::EndWith, memFile);
        if (fileMaps.empty())
            return false;

        auto firstMap = fileMaps.front();
        uintptr_t totalStart = firstMap.startAddress;
        uintptr_t lastEnd = firstMap.endAddress;

        for (size_t i = 1; i < fileMaps.size(); ++i)
        {
            const auto &it = fileMaps[i];
            if (firstMap.inode != 0 && it.inode == firstMap.inode && it.startAddress == lastEnd)
            {
                lastEnd = it.endAddress;
                continue;
            }
            break;
        }

        size_t totalSize = lastEnd - totalStart;
        return dumpMemToDisk(totalStart, totalSize, destination);
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

    size_t syscallMemOp(EPROCESS_VM_OP op, uintptr_t address, void *buffer, size_t len)
    {
        if (!address || !buffer || !len)
            return 0;

        const static pid_t pid = getpid();

        struct iovec lvec{.iov_base = buffer, .iov_len = 0};
        struct iovec rvec{.iov_base = reinterpret_cast<void *>(address), .iov_len = 0};

        ssize_t n = 0;
        size_t bytes_op = 0, remaining = len;
        bool page_mode = false;
        do
        {
            size_t remaining_or_pglen = remaining;
            if (page_mode)
                remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

            lvec.iov_len = remaining_or_pglen;
            rvec.iov_len = remaining_or_pglen;

            errno = 0;

            if (op == EPROCESS_VM_OP::READV)
                n = KT_EINTR_RETRY(syscall_process_vm_readv(pid, &lvec, 1, &rvec, 1, 0));
            else
                n = KT_EINTR_RETRY(syscall_process_vm_writev(pid, &lvec, 1, &rvec, 1, 0));

            if (n > 0)
            {
                remaining -= n;
                bytes_op += n;
                lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + n;
                rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + n;
            }
            else
            {
                if (n == -1)
                {
                    int err = errno;
                    if (err != EFAULT && err != EIO && err != EINVAL)
                    {
                        break;
                    }
                }
                if (page_mode)
                {
                    remaining -= remaining_or_pglen;
                    lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + remaining_or_pglen;
                    rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + remaining_or_pglen;
                }
            }
            page_mode = n == -1 || size_t(n) != remaining_or_pglen;
        } while (remaining > 0);
        return bytes_op;
    }

#elif __APPLE__

    kern_return_t getPageInfo(vm_address_t region, vm_region_submap_short_info_64 *info_out)
    {
        vm_size_t region_len = 0;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        unsigned int depth = 0x1000;
        return vm_region_recurse_64(mach_task_self(),
                                    &region,
                                    &region_len,
                                    &depth,
                                    (vm_region_recurse_info_t)info_out,
                                    &info_count);
    }

    bool memRead(const void *address, void *buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", address, buffer, len);

        if (!address)
        {
            KITTY_LOGE("memRead err address (%p) is null", address);
            return false;
        }

        if (!buffer)
        {
            KITTY_LOGE("memRead err buffer (%p) is null", buffer);
            return false;
        }

        if (!len)
        {
            KITTY_LOGE("memRead err invalid len");
            return false;
        }

        mach_vm_size_t nread = 0;
        kern_return_t kret = mach_vm_read_overwrite(mach_task_self(),
                                                    mach_vm_address_t(address),
                                                    mach_vm_size_t(len),
                                                    mach_vm_address_t(buffer),
                                                    &nread);
        if (kret != KERN_SUCCESS || nread != len)
        {
            KITTY_LOGE("memRead err vm_read failed - [ nread(%p) - kerror(%d) ]", (void *)nread, kret);
            return false;
        }

        return true;
    }

    /*
    refs to
    - https://github.com/evelyneee/ellekit/blob/main/ellekitc/ellekitc.c
    - CydiaSubstrate
    */
    Memory_Status memWrite(void *address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memWrite(%p, %p, %zu)", address, buffer, len);

        if (!address)
        {
            KITTY_LOGE("memWrite err address (%p) is null.", address);
            return KMS_INV_ADDR;
        }

        if (!buffer)
        {
            KITTY_LOGE("memWrite err buffer (%p) is null.", buffer);
            return KMS_INV_BUF;
        }

        if (!len)
        {
            KITTY_LOGE("memWrite err invalid len.");
            return KMS_INV_LEN;
        }

        task_t self_task = mach_task_self();
        mach_vm_address_t page_start = mach_vm_address_t(KT_PAGE_START(address));
        size_t page_len = KT_PAGE_LEN2(address, len);

        vm_region_submap_short_info_64 page_info = {};
        kern_return_t kret = getPageInfo(page_start, &page_info);
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err failed to get page info of address (%p) - kerror(%d).", address, kret);
            return KMS_ERR_GET_PAGEINFO;
        }

        // already has write perm
        if (page_info.protection & VM_PROT_WRITE)
        {
            kret = mach_vm_write(self_task,
                                 mach_vm_address_t(address),
                                 vm_offset_t(buffer),
                                 mach_msg_type_number_t(len));
            if (kret != KERN_SUCCESS)
            {
                KITTY_LOGE("memWrite err vm_write failed to write data to address (%p) - "
                           "kerror(%d).",
                           address,
                           kret);
                return KMS_ERR_VMWRITE;
            }
            return KMS_SUCCESS;
        }

#if 0
        // check for Substrate/ellekit MSHookMemory existance first
        if (findMSHookMemory(address, buffer, len))
            return KMS_SUCCESS;
#endif

        // copy-on-write, see vm_map_protect in vm_map.c
        kret = mach_vm_protect(self_task, page_start, page_len, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_protect(page: %p, len: %zu, prot: %d) COW failed - "
                       "kerror(%d).",
                       (void *)page_start,
                       page_len,
                       page_info.protection,
                       kret);
            return KMS_ERR_PROT;
        }

        kret = mach_vm_write(self_task, mach_vm_address_t(address), vm_offset_t(buffer), mach_msg_type_number_t(len));
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_write failed to write data to address (%p) - kerror(%d).", address, kret);
            return KMS_ERR_VMWRITE;
        }

        kret = mach_vm_protect(self_task, page_start, page_len, false, page_info.protection);
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_protect(page: %p, len: %zu, prot: %d) restore failed "
                       "- kerror(%d).",
                       (void *)page_start,
                       page_len,
                       page_info.protection,
                       kret);
            return KMS_ERR_PROT;
        }

        sys_icache_invalidate(reinterpret_cast<void *>(page_start), page_len);

        return KMS_SUCCESS;
    }

    MemoryFileInfo getBaseInfo()
    {
        uint32_t exeBufSize = 1024;
        std::vector<char> exeBuf(exeBufSize, 0);
        if (_NSGetExecutablePath(exeBuf.data(), &exeBufSize) == -1)
        {
            exeBuf.clear();
            exeBuf.resize(exeBufSize + 1, 0);
            _NSGetExecutablePath(exeBuf.data(), &exeBufSize);
        }

        const uint32_t imageCount = _dyld_image_count();
        int exeIdx = -1;

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const mach_header *hdr = _dyld_get_image_header(i);
            if (!hdr || hdr->filetype != MH_EXECUTE)
                continue;

            // first executable
            if (exeIdx == -1)
                exeIdx = i;

            const char *name = _dyld_get_image_name(i);
            if (!name || strlen(name) != strlen(exeBuf.data()) || strcmp(name, exeBuf.data()) != 0)
                continue;

            exeIdx = i;
            break;
        }

        MemoryFileInfo _info = {};

        if (exeIdx >= 0)
        {
            _info.index = exeIdx;
#ifdef __LP64__
            _info.header = (const mach_header_64 *)_dyld_get_image_header(exeIdx);
#else
            _info.header = _dyld_get_image_header(exeIdx);
#endif
            _info.name = _dyld_get_image_name(exeIdx);
            _info.address = _dyld_get_image_vmaddr_slide(exeIdx);
        }

        return _info;
    }

    MemoryFileInfo getMemoryFileInfo(const std::string &fileName)
    {
        MemoryFileInfo _info = {};

        if (fileName.empty())
            return _info;

        const uint32_t imageCount = _dyld_image_count();

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const char *name = _dyld_get_image_name(i);
            if (!name)
                continue;

            std::string fullpath(name);
            if (!KittyUtils::String::endsWith(fullpath, fileName))
                continue;

            _info.index = i;
#ifdef __LP64__
            _info.header = (const mach_header_64 *)_dyld_get_image_header(i);
#else
            _info.header = _dyld_get_image_header(i);
#endif
            _info.name = _dyld_get_image_name(i);
            _info.address = _dyld_get_image_vmaddr_slide(i);

            break;
        }

        return _info;
    }

    uintptr_t getAbsoluteAddress(const char *fileName, uintptr_t address)
    {
        MemoryFileInfo info = {};

        if (fileName)
            info = getMemoryFileInfo(fileName);
        else
            info = getBaseInfo();

        if (!info.address)
            return 0;

        return info.address + address;
    }

#endif // __APPLE__

} // namespace KittyMemory

#ifdef __APPLE__

#if 0
#ifndef kNO_SUBSTRATE
bool findMSHookMemory(void *dst, const void *src, size_t len)
{
    static bool checked = false;
    static void *fnPtr = nullptr;

    if (!checked)
    {
        fnPtr = (void*)KittyScanner::findSymbol("/usr/lib/libsubstrate.dylib", "_MSHookMemory");
        if (!fnPtr)
            fnPtr = (void*)KittyScanner::findSymbol("/usr/lib/libellekit.dylib", "_MSHookMemory");

        checked = true;
    }

    if (fnPtr)
    {
        reinterpret_cast<void (*)(void *, const void *, size_t)>(fnPtr)(dst, src, len);
        return true;
    }

    return false;
}
#else
bool findMSHookMemory(void *, const void *, size_t) { return false; }
#endif
#endif

namespace KittyScanner
{
    uintptr_t findSymbol(const KittyMemory::MemoryFileInfo &info, const std::string &symbol)
    {
        if (!info.header || !info.address || symbol.empty())
            return 0;

        uintptr_t slide = info.address;

#ifdef __LP64__
        struct mach_header_64 *header = (struct mach_header_64 *)info.header;
        const int lc_seg = LC_SEGMENT_64;
        struct segment_command_64 *curr_seg_cmd = nullptr;
        struct segment_command_64 *linkedit_segment_cmd = nullptr;
        struct symtab_command *symtab_cmd = nullptr;
        struct nlist_64 *symtab = nullptr;
#else
        struct mach_header *header = (struct mach_header *)info.header;
        const int lc_seg = LC_SEGMENT;
        struct segment_command *curr_seg_cmd = nullptr;
        struct segment_command *linkedit_segment_cmd = nullptr;
        struct symtab_command *symtab_cmd = nullptr;
        struct nlist *symtab = nullptr;
#endif

        uintptr_t curr = uintptr_t(header) + sizeof(*header);
        for (uint32_t i = 0; i < header->ncmds; i++, curr += curr_seg_cmd->cmdsize)
        {
            *(uintptr_t *)&curr_seg_cmd = curr;

            if (curr_seg_cmd->cmd == lc_seg && (strcmp(curr_seg_cmd->segname, SEG_LINKEDIT) == 0))
                *(uintptr_t *)&linkedit_segment_cmd = curr;
            else if (curr_seg_cmd->cmd == LC_SYMTAB)
                *(uintptr_t *)&symtab_cmd = curr;
        }

        if (!linkedit_segment_cmd || !symtab_cmd)
            return 0;

        uintptr_t linkedit_base = (slide + linkedit_segment_cmd->vmaddr) - linkedit_segment_cmd->fileoff;
        *(uintptr_t *)&symtab = (linkedit_base + symtab_cmd->symoff);
        char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

        for (uint32_t i = 0; i < symtab_cmd->nsyms; i++)
        {
            if (symtab[i].n_value == 0)
                continue;

            std::string curr_sym_str = std::string(strtab + symtab[i].n_un.n_strx);

            // KITTY_LOGI("syms[%d] = [%{public}s, %p]", i, curr_sym_str.c_str(),
            // (void*)symtab[i].n_value);

            if (curr_sym_str.empty() || curr_sym_str != symbol)
                continue;

            return slide + symtab[i].n_value;
        }

        return 0;
    }

    uintptr_t findSymbol(const std::string &lib, const std::string &symbol)
    {
        return findSymbol(KittyMemory::getMemoryFileInfo(lib), symbol);
    }
} // namespace KittyScanner

#endif // __APPLE__
