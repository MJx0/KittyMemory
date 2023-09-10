//
//  KittyMemory.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "KittyMemory.h"
#include "KittyUtils.h"
#include <map>
#include <dlfcn.h>

namespace KittyMemory {

    int setAddressProtection(void *address, size_t length, int protection)
    {
        uintptr_t pageStart = _PAGE_START_OF_(address);
        uintptr_t pageLen = _PAGE_LEN_OF_(address, length);
        int ret = mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection);
        KITTY_LOGD("mprotect(%p, %zu, %d) = %d", address, length, protection, ret);
        return ret;
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

    bool memRead(void *address, const void *buffer, size_t len)
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

        memcpy(address, buffer, len);

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

    std::vector<ProcMap> getMapsByName(const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGD("getMapsByName(%s)", name.c_str());

        std::vector<ProcMap> retMaps;

        auto maps = getAllMaps();
        for(auto &it : maps) {
            if (it.isValid() && !it.isUnknown() && strstr(it.pathname.c_str(), name.c_str())) {
                retMaps.push_back(it);
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

    ProcMap getBaseMapOf(const std::string& name)
    {
        ProcMap retMap{};

        if (name.empty())
            return retMap;

        bool isZippedInAPK = false;
        auto maps = getMapsByName(name);
        if (maps.empty())
        {
            // some apps use dlopen on zipped libraries like base.apk!/lib/xxx/libxxx.so
            // so we'll search in app's base.apk maps too
            maps = getMapsByName("==/base.apk");
            if (maps.empty()) {
                return retMap;
            }
            isZippedInAPK = true;
        }

        for (auto &it: maps) {
            if (!it.isValid() || it.isUnknown() || !it.readable || it.writeable || !it.is_private) continue;
            if (memcmp((const void *) it.startAddress, "\177ELF", 4) != 0) continue;

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

}