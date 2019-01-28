//
//  KittyMemory.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "KittyMemory.h"

using KittyMemory::Memory_Status;


bool KittyMemory::ProtectAddr(void *addr, size_t length, int protection) {
   void     *pageStart = (void *)_PAGE_START_OF_(addr);
   uintptr_t pageLen   = _PAGE_LEN_OF_(addr, length);
   return (
     mprotect(pageStart, pageLen, protection) != -1
 );
}


Memory_Status KittyMemory::Write(void *addr, const void *buffer, size_t len) {
    if (addr == NULL)
        return INV_ADDR;

    if (buffer == NULL)
        return INV_BUF;

    if (len < 1)
        return INV_LEN;

    if (!ProtectAddr(addr, len, _PROT_RWX_))
        return INV_PROT;

    if (memcpy(addr, buffer, len) != NULL && ProtectAddr(addr, len, _PROT_RX_))
        return SUCCESS;

    return FAILED;
}


Memory_Status KittyMemory::Read(void *buffer, const void *addr, size_t len) {
    if (addr == NULL)
        return INV_ADDR;

    if (buffer == NULL)
        return INV_BUF;

    if (len < 1)
        return INV_LEN;

    if (memcpy(buffer, addr, len) != NULL)
        return SUCCESS;

    return FAILED;
}


std::string KittyMemory::read2HexStr(const void *addr, size_t len) {
    char temp[len];
    memset(temp, 0, len);
	
    const size_t bufferLen = len * 2 + 1;
    char buffer[bufferLen];
    memset(buffer, 0, bufferLen);

    std::string ret = "0x";

    if (Read(temp, addr, len) != SUCCESS)
        return ret;

    for (int i = 0; i < len; i++) {
        sprintf(&buffer[i * 2], "%02X", (unsigned char) temp[i]);
    }

    ret += buffer;
    return ret;
}

uintptr_t KittyMemory::getLibraryBase(const char *libName) {
    uintptr_t retAddr = 0;
	
    char fileName[255];
    memset(fileName, 0, sizeof(fileName));
	
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    snprintf(fileName, sizeof(fileName), "/proc/%d/maps", getpid());
    FILE *fp = fopen(fileName, "rt");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, libName) != NULL) {
                retAddr = (uintptr_t) strtoul(buffer, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return retAddr;
}

uintptr_t KittyMemory::getAbsoluteAddress(const char *libName, uintptr_t relativeAddr) {
    uintptr_t base = getLibraryBase(libName);
    if (base == 0)
        return 0;
    return (base + relativeAddr);
}
