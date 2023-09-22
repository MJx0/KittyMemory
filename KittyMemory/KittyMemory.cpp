//
//  KittyMemory.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "KittyMemory.hpp"
#include "KittyUtils.hpp"

#ifdef __ANDROID__
#include <map>
#include <dlfcn.h>

#elif __APPLE__
bool findMSHookMemory(void *dst, const void *src, size_t len);
extern "C" kern_return_t mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
                                       mach_vm_offset_t, int, vm_map_t, mach_vm_address_t,
                                       boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);
#endif

namespace KittyMemory {

    int setAddressProtection(void *address, size_t length, int protection)
    {
        uintptr_t pageStart = _PAGE_START_OF_(address);
        uintptr_t pageLen = _PAGE_LEN_OF_(address, length);
        int ret = mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection);
        KITTY_LOGD("mprotect(%p, %zu, %d) = %d", address, length, protection, ret);
        return ret;
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
            KITTY_LOGE("memWrite err invalid len");
            return false;
        }

        memcpy(buffer, address, len);
        return true;
    }

#ifdef __ANDROID__

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

    std::vector<ProcMap> getMapsEqual(const std::string& name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsEqual(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        auto maps = getAllMaps();
        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && it.pathname == name) {
                retMaps.push_back(it);
            }
        }

        return retMaps;
    }

    std::vector<ProcMap> getMapsContain(const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsContain(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        auto maps = getAllMaps();
        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && strstr(it.pathname.c_str(), name.c_str())) {
                retMaps.push_back(it);
            }
        }

        return retMaps;
    }

    std::vector<ProcMap> getMapsEndWith(const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsEndWith(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        auto maps = getAllMaps();
        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && it.pathname.length() >= name.length()) {
                if (it.pathname.compare(it.pathname.length() - name.length(), name.length(), name) == 0) {
                    retMaps.push_back(it);
                }
            }
        }

        return retMaps;
    }

    ProcMap getAddressMap(const void *address)
    {
        KITTY_LOGD("getAddressMap(%p)", address);

        if (!address) return {};

        ProcMap retMap{};

        auto maps = getAllMaps();
        for(auto &it : maps) {
            if (it.isValid() && (uintptr_t)address >= it.startAddress && (uintptr_t)address <= it.endAddress) {
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

        for (auto &it: maps) {
            if (it.isUnknown() || it.writeable || !it.is_private || !it.isValidELF()) continue;

            // skip dladdr check for linker/linker64
            if (strstr(it.pathname.c_str(), "/system/bin/linker")) {
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
            if (strstr(info.dli_fname, name.c_str())) {
                retMap = it;
                retMap.pathname = info.dli_fname;
                break;
            }
        }

        return retMap;
    }

#elif __APPLE__

    kern_return_t getPageInfo(void *page_start, vm_region_submap_short_info_64 *info_out)
    {
      vm_address_t region = reinterpret_cast<vm_address_t>(page_start);
      vm_size_t region_len = 0;
      mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
      unsigned int depth = 0;
      return vm_region_recurse_64(mach_task_self(), &region, &region_len,
                                  &depth, (vm_region_recurse_info_t)info_out,
                                  &info_count);
    }

    /*
    refs to
    - https://github.com/asLody/whale/blob/master/whale/src/platform/memory.cc
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

        void *page_start = reinterpret_cast<void *>(_PAGE_START_OF_(address));
        void *page_offset = reinterpret_cast<void *>(_PAGE_OFFSET_OF_(address));
        size_t page_len = _PAGE_LEN_OF_(address, len);

        vm_region_submap_short_info_64 page_info;
        if (getPageInfo(page_start, &page_info) != KERN_SUCCESS) {
            KITTY_LOGE("memWrite err failed to get page info of address (%p).", address);
            return KMS_ERR_GET_PAGEINFO;
        }

        // already has write perm
        if (page_info.protection & VM_PROT_WRITE)
        {
            memcpy(address, buffer, len);
            return KMS_SUCCESS;
        }

        // check for Substrate/ellekit MSHookMemory existance first
        if (findMSHookMemory(address, buffer, len))
            return KMS_SUCCESS;

        // create new map, copy our code to it then remap it over target map

        void *new_map = mmap(nullptr, page_len, _PROT_RW_, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        if (!new_map) {
            KITTY_LOGE("memWrite err mmap(%zu) failed.", page_len);
            return KMS_ERR_MMAP;
        }

        task_t self_task = mach_task_self();

        // copy original page content to new
        if (vm_copy(self_task, reinterpret_cast<vm_address_t>(page_start), page_len,
                    reinterpret_cast<vm_address_t>(new_map)) != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_copy(%p, %zu, %p) failed.", page_start, page_len, new_map);
            munmap(new_map, page_len);
            return KMS_ERR_PROT;
        }

        // write patch code to new
        void *dst = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(new_map) + reinterpret_cast<uintptr_t>(page_offset));
        memcpy(dst, buffer, len);

        // original prot on new
        if (mprotect(new_map, page_len, (page_info.protection & (_PROT_RWX_))) == -1)
        {
            KITTY_LOGE("memWrite err failed to set new_map to original protection (new_map: %p, len: %zu, prot: %d).",
                       new_map, page_len, page_info.protection);
            munmap(new_map, page_len);
            return KMS_ERR_PROT;
        }

        // remap
        vm_prot_t cur_protection, max_protection;
        mach_vm_address_t mach_vm_page_start = reinterpret_cast<mach_vm_address_t>(page_start);
        if (mach_vm_remap(self_task, &mach_vm_page_start, page_len, 0, VM_FLAGS_OVERWRITE,
                          self_task, reinterpret_cast<mach_vm_address_t>(new_map),
                          TRUE, &cur_protection, &max_protection,
                          page_info.inheritance) != KERN_SUCCESS)
        {
            KITTY_LOGE("memWrite err vm_remap(page: %p, len: %zu, prot: %d) failed.",
                       page_start, page_len, page_info.protection);
            munmap(new_map, page_len);
            return KMS_ERR_REMAP;
        }

        munmap(new_map, page_len);
        return KMS_SUCCESS;
    }

    MemoryFileInfo getBaseInfo()
    {
        MemoryFileInfo _info;

        const uint32_t imageCount = _dyld_image_count();

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const mach_header *hdr = _dyld_get_image_header(i);
            if (!hdr || hdr->filetype != MH_EXECUTE) continue;

            // first executable
            _info.index = i;
            _info.header = _dyld_get_image_header(i);
            _info.name = _dyld_get_image_name(i);
            _info.address = _dyld_get_image_vmaddr_slide(i);

            break;
        }

        return _info;
    }

    MemoryFileInfo getMemoryFileInfo(const std::string& fileName)
    {
        MemoryFileInfo _info;

        const uint32_t imageCount = _dyld_image_count();

        for (uint32_t i = 0; i < imageCount; i++)
        {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;

            std::string fullpath(name);

            if (fullpath.length() < fileName.length() || fullpath.compare(fullpath.length() - fileName.length(), fileName.length(), fileName) != 0)
                continue;

            _info.index = i;
            _info.header = _dyld_get_image_header(i);
            _info.name = _dyld_get_image_name(i);
            _info.address = _dyld_get_image_vmaddr_slide(i);

            break;
        }
        return _info;
    }

    uintptr_t getAbsoluteAddress(const char *fileName, uintptr_t address)
    {
        MemoryFileInfo info;

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

#if !defined(kNO_SUBSTRATE) && defined(THEOS_INSTANCE_NAME)
#include <substrate.h>
bool findMSHookMemory(void *dst, const void *src, size_t len)
{
    static bool checked = false;
    static void *fnPtr = nullptr;

    if (!checked)
    {
        MSImageRef image = MSGetImageByName("/usr/lib/libsubstrate.dylib");
        if(!image)
            image = MSGetImageByName("/usr/lib/libellekit.dylib");

        if(image)
            fnPtr = MSFindSymbol(image, "_MSHookMemory");

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
bool findMSHookMemory(void *dst, const void *src, size_t len) { return false; }
#endif

#endif // __APPLE__