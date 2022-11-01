//
//  KittyMemory.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "KittyMemory.h"
#include <map>
#include <android/log.h>

namespace KittyMemory {

    int setAddressProtection(void *address, size_t length, int protection)
    {
        uintptr_t pageStart = _PAGE_START_OF_(address);
        uintptr_t pageLen = _PAGE_LEN_OF_(address, length);
        int ret = mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection);
        KITTY_LOGI("mprotect(%p, %zu, %d) = %d", address, length, protection, ret);
        return ret;
    }

    bool memWrite(void *address, const void *buffer, size_t len)
    {
        KITTY_LOGI("memWrite(%p, %p, %zu)", address, buffer, len);

        if (!address) {
            KITTY_LOGE("memWrite err address (%p) is null", address);
            return false;
        }

        if (!buffer) {
            KITTY_LOGE("memWrite err buffer (%p) is null", buffer);
            return false;
        }

        if (len < 1 || len > INT_MAX) {
            KITTY_LOGE("memWrite err invalid len (%zu) < 1 || > INT_MAX", len);
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
        KITTY_LOGI("memRead(%p, %p, %zu)", address, buffer, len);

        if (!address) {
            KITTY_LOGE("memRead err address (%p) is null", address);
            return false;
        }

        if (!buffer) {
            KITTY_LOGE("memRead err buffer (%p) is null", buffer);
            return false;
        }

        if (len < 1 || len > INT_MAX) {
            KITTY_LOGE("memRead err invalid len (%zu) < 1 || > INT_MAX", len);
            return false;
        }

        memcpy(address, buffer, len);

        return true;
    }

    std::string read2HexStr(const void *address, size_t len)
    {
        std::string temp(len, ' ');
        if (!memRead(&temp[0], address, len)) return "";

        std::string ret(len * 2, ' ');
        for (int i = 0; i < len; i++) {
            sprintf(&ret[i * 2], "%02X", (unsigned char) temp[i]);
        }
        return ret;
    }

    std::vector<ProcMap> getAllMaps()
    {
        std::vector<ProcMap> retMaps;
        char line[512] = {0};

        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
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
        }

        if (retMaps.empty()) {
            KITTY_LOGE("getAllMaps err couldn't find any map");
        }
        return retMaps;
    }

    std::vector<ProcMap> getMapsByName(const std::string &name)
    {
        if (name.empty()) return {};

        KITTY_LOGI("getMapsByName(%s)", name.c_str());

        std::vector<ProcMap> retMaps;
        char line[512] = {0};

        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, name.c_str())) {
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
                    // KITTY_LOGI("getMapsByName [%llx-%llx %s %llx %s %lu %s]",
                    // map.startAddress, map.endAddress, perms, map.offset,
                    // map.dev.empty() ? "null" : map.dev.c_str(),
                    // map.inode, map.pathname.empty() ? "null" : map.pathname.c_str());
                }
            }
            fclose(fp);
        }

        if (retMaps.empty()) {
            KITTY_LOGE("getMapsByName err couldn't find any map with name (%s)", name.c_str());
        }
        return retMaps;
    }

    ProcMap getAddressMap(const void *address)
    {
        KITTY_LOGI("getAddressMap(%p)", address);

        if (!address) return {};

        ProcMap map;
        char line[512] = {0};
        unsigned long long startAddress = 0, endAddress = 0;

        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                sscanf(line, "%llx-%llx", &startAddress, &endAddress);
                if ((uintptr_t)address >= startAddress && (uintptr_t)address <= endAddress) {

                    char perms[5] = {0}, dev[11] = {0}, pathname[256] = {0};
                    // parse a line in maps file
                    // (format) startAddress-endAddress perms offset dev inode pathname
                    sscanf(line, "%*llx-%*llx %s %llx %s %lu %s",
                           perms, &map.offset, dev, &map.inode, pathname);

                    map.startAddress = startAddress;
                    map.endAddress = endAddress;
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

                    // KITTY_LOGI("Address (%p) map = (%llx-%llx %s %llx %s %lu %s)", address,
                    // map.startAddress, map.endAddress, perms[0] == 0 ? "null" : perms,
                    // map.offset, map.dev.empty() ? "null" : map.dev.c_str(),
                    // map.inode, map.pathname.empty() ? "null" : map.pathname.c_str());

                    break;
                }
            }
            fclose(fp);
        }

        if (!map.isValid()) {
            KITTY_LOGE("getAddressMap err couldn't find any map with address (%p)",
                       address);
        }
        return map;
    }

    ProcMap getLibraryBaseMap(const std::vector<ProcMap> &maps)
    {
        ProcMap retMap{};

        if (maps.empty())
            return retMap;   
        
        for (auto &it : maps)
        {
            if (!it.isValid() || it.writeable || !it.is_private) continue;

            if (memcmp((const void *)it.startAddress, "\177ELF", 4) == 0)
            {
                retMap = it;
                // sometimes both r--p and r-xp could have a valid elf header,
                // don't break here because we need the last map with a valid elf header.
            }
        }
        return retMap;
    }

    ProcMap getLibraryBaseMap(const std::string& name)
    {
        return getLibraryBaseMap(getMapsByName(name));
    }

}