//
//  KittyMemory.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "KittyMemory.hpp"

#ifdef __APPLE__
#if 0
bool findMSHookMemory(void *dst, const void *src, size_t len);
#endif
extern "C"
{
    kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
    
    kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
    
    kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
}
#endif

namespace KittyMemory {

#ifdef __ANDROID__
    
    int setAddressProtection(const void *address, size_t length, int protection)
    {
        uintptr_t pageStart = KT_PAGE_START(address);
        uintptr_t pageLen = KT_PAGE_LEN2(address, length);
        int ret = mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection);
        KITTY_LOGD("mprotect(%p, %zu, %d) = %d", address, length, protection, ret);
        return ret;
    }

    bool memRead(const void* address, void* buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", address, buffer, len);

        if (!address) {
            KITTY_LOGE("memRead err address (%p) is null", address);
            return false;
        }

        if (!buffer) {
            KITTY_LOGE("memRead err buffer (%p) is null", buffer);
            return false;
        }

        if (!len) {
            KITTY_LOGE("memRead err invalid len");
            return false;
        }

        ProcMap addressMap = getAddressMap(address);
        if (!addressMap.isValid()) {
            KITTY_LOGE("memRead err couldn't find address (%p) in any map", address);
            return false;
        }

        if (addressMap.protection & PROT_READ) {
            memcpy(buffer, address, len);
            return true;
        }

        if (setAddressProtection(address, len, addressMap.protection | PROT_READ) != 0) {
            KITTY_LOGE("memRead err couldn't add write perm to address (%p, len: %zu, prot: %d)",
                address, len, addressMap.protection);
            return false;
        }

        memcpy(buffer, address, len);

        if (setAddressProtection(address, len, addressMap.protection) != 0) {
            KITTY_LOGE("memRead err couldn't revert protection of address (%p, len: %zu, prot: %d)",
                address, len, addressMap.protection);
            return false;
        }

        return true;
    }

    bool memWrite(void *address, const void *buffer, size_t len)
    {
        KITTY_LOGD("memWrite(%p, %p, %zu)", address, buffer, len);

        if (!address) {
            KITTY_LOGE("memWrite err address (%p) is null", address);
            return false;
        }

        if (!buffer) {
            KITTY_LOGE("memWrite err buffer (%p) is null", buffer);
            return false;
        }

        if (!len) {
            KITTY_LOGE("memWrite err invalid len");
            return false;
        }

        ProcMap addressMap = getAddressMap(address);
        if (!addressMap.isValid()) {
            KITTY_LOGE("memWrite err couldn't find address (%p) in any map", address);
            return false;
        }

        if (addressMap.protection & PROT_WRITE) {
            memcpy(address, buffer, len);
            return true;
        }

        if (setAddressProtection(address, len, addressMap.protection | PROT_WRITE) != 0) {
            KITTY_LOGE("memWrite err couldn't add write perm to address (%p, len: %zu, prot: %d)",
                            address, len, addressMap.protection);
            return false;
        }

        memcpy(address, buffer, len);

        if (setAddressProtection(address, len, addressMap.protection) != 0) {
            KITTY_LOGE("memWrite err couldn't revert protection of address (%p, len: %zu, prot: %d)",
                            address, len, addressMap.protection);
            return false;
        }

        return true;
    }

    std::string getProcessName()
    {
        const char *file = "/proc/self/cmdline";
        char cmdline[128] = {0};
        FILE *fp = fopen(file, "r");
        if (!fp) {
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
        if (!fp) {
            KITTY_LOGE("Couldn't open file %s.", file);
            return retMaps;
        }

        while (fgets(line, sizeof(line), fp)) {
            ProcMap map;

            char perms[5] = {0}, dev[11] = {0}, pathname[256] = {0};
            // parse a line in maps file
            // (format) startAddress-endAddress perms offset dev inode pathname
            sscanf(line, "%llx-%llx %s %llx %s %lu %s",
                   &map.startAddress, &map.endAddress,
                   perms, &map.offset, dev, &map.inode, pathname);

            map.length = map.endAddress - map.startAddress;
            map.dev = dev;
            map.pathname = pathname;

            if (perms[0] == 'r') {
                map.protection |= PROT_READ;
                map.readable = true;
            }
            if (perms[1] == 'w') {
                map.protection |= PROT_WRITE;
                map.writeable = true;
            }
            if (perms[2] == 'x') {
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

        if (retMaps.empty()) {
            KITTY_LOGE("getAllMaps err couldn't find any map");
        }
        return retMaps;
    }

    std::vector<ProcMap> getMapsEqual(const std::vector<ProcMap> &maps, const std::string& name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsEqual(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && it.pathname == name) {
                retMaps.push_back(it);
            }
        }

        return retMaps;
    }

    std::vector<ProcMap> getMapsContain(const std::vector<ProcMap> &maps, const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsContain(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && strstr(it.pathname.c_str(), name.c_str())) {
                retMaps.push_back(it);
            }
        }

        return retMaps;
    }

    std::vector<ProcMap> getMapsEndWith(const std::vector<ProcMap> &maps, const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsEndWith(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && KittyUtils::String::EndsWith(it.pathname, name)) {
                retMaps.push_back(it);
            }
        }

        return retMaps;
    }

    ProcMap getAddressMap(const std::vector<ProcMap> &maps, const void *address)
    {
        KITTY_LOGD("getAddressMap(%p)", address);

        if (!address) return {};

        ProcMap retMap{};

        for(auto &it : maps) {
            if (it.isValid() && it.contains((uintptr_t)address)) {
                retMap = it;
                break;
            }
        }

        return retMap;
    }

    ProcMap getElfBaseMap(const std::string& name)
    {
        ProcMap retMap{};

        if (name.empty())
            return retMap;

        bool isZippedInAPK = false;
        auto maps = getMapsEndWith(name);
        if (maps.empty())
        {
            // some apps use dlopen on zipped libraries like xxx.apk!/lib/xxx/libxxx.so
            // so we'll search in app's base.apk maps too
            maps = getMapsEndWith(".apk");
            if (maps.empty()) {
                return retMap;
            }
            isZippedInAPK = true;
        }

        for (auto &it: maps)
        {
            if (!it.readable || it.offset != 0 || it.isUnknown() || it.inode == 0 || !it.is_private || !it.isValidELF())
                continue;

            // skip dladdr check for linker/linker64
            if (strstr(it.pathname.c_str(), "/bin/linker")) {
                retMap = it;
                break;
            }

            Dl_info info{};
            int rt = dladdr((void *) it.startAddress, &info);
            // check dli_fname and dli_fbase if NULL
            if (rt == 0 || !info.dli_fname || !info.dli_fbase || it.startAddress != (uintptr_t) info.dli_fbase)
                continue;

            if (!isZippedInAPK) {
                retMap = it;
                break;
            }

            // if library is zipped inside base.apk, compare dli_fname and fix pathname
            if (KittyUtils::String::EndsWith(info.dli_fname, name)) {
                retMap = it;
                retMap.pathname = info.dli_fname;
                break;
            }
        }

        return retMap;
    }

#elif __APPLE__

    kern_return_t getPageInfo(vm_address_t region, vm_region_submap_short_info_64 *info_out)
    {
      vm_size_t region_len = 0;
      mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
      unsigned int depth = 0x1000;
      return vm_region_recurse_64(mach_task_self(), &region, &region_len,
                                  &depth, (vm_region_recurse_info_t)info_out,
                                  &info_count);
    }

    bool memRead(const void *address, void *buffer, size_t len)
    {
        KITTY_LOGD("memRead(%p, %p, %zu)", address, buffer, len);

        if (!address) {
            KITTY_LOGE("memRead err address (%p) is null", address);
            return false;
        }

        if (!buffer) {
            KITTY_LOGE("memRead err buffer (%p) is null", buffer);
            return false;
        }

        if (!len) {
            KITTY_LOGE("memRead err invalid len");
            return false;
        }
        
        mach_vm_size_t nread = 0;
        kern_return_t kret = mach_vm_read_overwrite(mach_task_self(), mach_vm_address_t(address), mach_vm_size_t(len), mach_vm_address_t(buffer), &nread);
        if (kret != KERN_SUCCESS || nread != len) {
            KITTY_LOGE("memRead err vm_read failed - [ nread(%p) - kerror(%d) ]",
                       (void*)nread, kret);
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
        
        if (!address) {
            KITTY_LOGE("memWrite err address (%p) is null.", address);
            return KMS_INV_ADDR;
        }
        
        if (!buffer) {
            KITTY_LOGE("memWrite err buffer (%p) is null.", buffer);
            return KMS_INV_BUF;
        }
        
        if (!len) {
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
            KITTY_LOGE("memWrite err failed to get page info of address (%p) - kerror(%d).",
                       address, kret);
            return KMS_ERR_GET_PAGEINFO;
        }
        
        // already has write perm
        if (page_info.protection & VM_PROT_WRITE)
        {
            kret = mach_vm_write(self_task, mach_vm_address_t(address), vm_offset_t(buffer), mach_msg_type_number_t(len));
            if (kret != KERN_SUCCESS)
            {
                KITTY_LOGE("memWrite err vm_write failed to write data to address (%p) - kerror(%d).",
                           address, kret);
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
        kret = mach_vm_protect(self_task, page_start, page_len, false,
                               VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_protect(page: %p, len: %zu, prot: %d) COW failed - kerror(%d).",
                       (void*)page_start, page_len, page_info.protection, kret);
            return KMS_ERR_PROT;
        }
        
        kret = mach_vm_write(self_task, mach_vm_address_t(address), vm_offset_t(buffer), mach_msg_type_number_t(len));
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_write failed to write data to address (%p) - kerror(%d).",
                       address, kret);
            return KMS_ERR_VMWRITE;
        }
        
        kret = mach_vm_protect(self_task, page_start, page_len, false, page_info.protection);
        if (kret != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_protect(page: %p, len: %zu, prot: %d) restore failed - kerror(%d).",
                       (void*)page_start, page_len, page_info.protection, kret);
            return KMS_ERR_PROT;
        }
        
        sys_icache_invalidate(reinterpret_cast<void*>(page_start), page_len);
        
        return KMS_SUCCESS;
    }

    MemoryFileInfo getBaseInfo()
    {
        uint32_t exeBufSize = 1024;
        std::vector<char> exeBuf(exeBufSize, 0);
        if (_NSGetExecutablePath(exeBuf.data(), &exeBufSize) == -1)
        {
            exeBuf.clear();
            exeBuf.resize(exeBufSize+1, 0);
            _NSGetExecutablePath(exeBuf.data(), &exeBufSize);
        }

        const uint32_t imageCount = _dyld_image_count();
        int exeIdx = -1;

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const mach_header *hdr = _dyld_get_image_header(i);
            if (!hdr || hdr->filetype != MH_EXECUTE) continue;
            
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
            _info.header = (const mach_header_64*)_dyld_get_image_header(exeIdx);
#else
            _info.header = _dyld_get_image_header(exeIdx);
#endif
            _info.name = _dyld_get_image_name(exeIdx);
            _info.address = _dyld_get_image_vmaddr_slide(exeIdx);
        }
        
        return _info;
    }

    MemoryFileInfo getMemoryFileInfo(const std::string& fileName)
    {
        MemoryFileInfo _info = {};
        
        if (fileName.empty())
            return _info;

        const uint32_t imageCount = _dyld_image_count();

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;

            std::string fullpath(name);
            if (!KittyUtils::String::EndsWith(fullpath, fileName))
                continue;

            _info.index = i;
#ifdef __LP64__
            _info.header = (const mach_header_64*)_dyld_get_image_header(i);
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

} // KittyMemory


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
        struct mach_header *header = (struct mach_header *)libInfo.header;
        const int lc_seg = LC_SEGMENT;
        struct segment_command *curr_seg_cmd = nullptr;
        struct segment_command *linkedit_segment_cmd = nullptr;
        struct symtab_command *symtab_cmd = nullptr;
        struct nlist *symtab = nullptr;
#endif
        
        uintptr_t curr = uintptr_t(header) + sizeof(*header);
        for (uint32_t i = 0; i < header->ncmds; i++, curr += curr_seg_cmd->cmdsize)
        {
            *(uintptr_t*)&curr_seg_cmd = curr;
            
            if (curr_seg_cmd->cmd == lc_seg && (strcmp(curr_seg_cmd->segname, SEG_LINKEDIT) == 0))
                *(uintptr_t*)&linkedit_segment_cmd = curr;
            else if (curr_seg_cmd->cmd == LC_SYMTAB)
                *(uintptr_t*)&symtab_cmd = curr;
        }
        
        if (!linkedit_segment_cmd || !symtab_cmd)
            return 0;
        
        uintptr_t linkedit_base = (slide + linkedit_segment_cmd->vmaddr) - linkedit_segment_cmd->fileoff;
        *(uintptr_t*)&symtab = (linkedit_base + symtab_cmd->symoff);
        char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
        
        for (uint32_t i = 0; i < symtab_cmd->nsyms; i++)
        {
            if (symtab[i].n_value == 0)
                continue;
            
            std::string curr_sym_str = std::string(strtab + symtab[i].n_un.n_strx);
            
            //KITTY_LOGI("syms[%d] = [%{public}s, %p]", i, curr_sym_str.c_str(), (void*)symtab[i].n_value);
            
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
}

#endif // __APPLE__