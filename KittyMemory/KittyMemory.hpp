//
//  KittyMemory.hpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#pragma once

#include <inttypes.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <vector>

#ifdef __ANDROID__
#include <dlfcn.h>
#include <unordered_map>

#elif __APPLE__
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>
#include <libkern/OSCacheControl.h>

#endif

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

namespace KittyMemory
{
    /*
     * Reads an address content into a buffer
     */
    bool memRead(const void *address, void *buffer, size_t len);

#ifdef __ANDROID__

    class ProcMap
    {
    public:
        uintptr_t startAddress;
        uintptr_t endAddress;
        size_t length;
        int protection;
        bool readable, writeable, executable, is_private, is_shared, is_ro, is_rw, is_rx;
        uintptr_t offset;
        std::string dev;
        unsigned long inode;
        std::string pathname;

        ProcMap()
            : startAddress(0), endAddress(0), length(0), protection(0), readable(false), writeable(false),
              executable(false), is_private(false), is_shared(false), is_ro(false), is_rw(false), is_rx(false),
              offset(0), inode(0)
        {
        }

        inline bool isValid() const
        {
            return (startAddress && endAddress && length);
        }
        inline bool isUnknown() const
        {
            return pathname.empty();
        }
        inline bool isValidELF() const
        {
            return isValid() && length > 4 && readable && memcmp((const void *)startAddress, "\177ELF", 4) == 0;
        }
        inline bool contains(uintptr_t address) const
        {
            return address >= startAddress && address < endAddress;
        }
        inline std::string toString() const
        {
            return KittyUtils::String::Fmt("%" PRIxPTR "-%" PRIxPTR " %c%c%c%c %" PRIxPTR " %s %lu %s", startAddress, endAddress,
                                           readable ? 'r' : '-', writeable ? 'w' : '-', executable ? 'x' : '-',
                                           is_private ? 'p' : 's', offset, dev.c_str(), inode, pathname.c_str());
        }
    };

    enum class EProcMapFilter
    {
        Equal,
        Contains,
        StartWith,
        EndWith
    };

    /*
     * mprotect wrapper
     */
    int memProtect(const void *address, size_t length, int protection);

    /*
     * Writes buffer content to an address
     */
    bool memWrite(void *address, const void *buffer, size_t len);

    /*
     * /proc/self/cmdline
     */
    std::string getProcessName();

    /*
     * Gets info of all maps in current process
     */
    std::vector<ProcMap> getAllMaps();

    /*
     * Gets info of all maps with filter @name in current process
     */
    std::vector<ProcMap> getMaps(EProcMapFilter filter, const std::string &name,
                                 const std::vector<ProcMap> &maps = getAllMaps());

    /*
     * Gets map info of an address in self process
     */
    ProcMap getAddressMap(const void *address, const std::vector<ProcMap> &maps = getAllMaps());
    /*
     * Gets map info of an address in self process
     */
    inline ProcMap getAddressMap(uintptr_t address, const std::vector<ProcMap> &maps = getAllMaps())
    {
        return getAddressMap((const void *)address, maps);
    }

    /**
     * Dump memory range
     */
    bool dumpMemToDisk(uintptr_t address, size_t size, const std::string &destination);

    /**
     * Dump memory mapped file
     */
    bool dumpMemFileToDisk(const std::string &memFile, const std::string &destination);

    enum class EPROCESS_VM_OP
    {
        READV,
        WRITEV
    };

    size_t syscallMemOp(EPROCESS_VM_OP op, uintptr_t address, void *buffer, size_t len);

    inline size_t syscallMemRead(uintptr_t address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::READV, address, buffer, len);
    }

    inline size_t syscallMemRead(void *address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::READV, uintptr_t(address), buffer, len);
    }

    inline size_t syscallMemWrite(uintptr_t address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::WRITEV, address, buffer, len);
    }

    inline size_t syscallMemWrite(void *address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::WRITEV, uintptr_t(address), buffer, len);
    }

#elif __APPLE__

    enum Memory_Status
    {
        KMS_FAILED = 0,
        KMS_SUCCESS,
        KMS_INV_ADDR,
        KMS_INV_LEN,
        KMS_INV_BUF,
        KMS_ERR_PROT,
        KMS_ERR_GET_PAGEINFO,
        KMS_ERR_VMWRITE,
    };

    struct seg_data_t
    {
        uintptr_t start, end;
        unsigned long size;
        seg_data_t() : start(0), end(0), size(0)
        {
        }
    };

    class MemoryFileInfo
    {
    public:
        uint32_t index;
#ifdef __LP64__
        const mach_header_64 *header;
#else
        const mach_header *header;
#endif
        const char *name;
        intptr_t address;

        MemoryFileInfo() : index(0), header(nullptr), name(nullptr), address(0)
        {
        }

        inline seg_data_t getSegment(const char *seg_name) const
        {
            seg_data_t data{};
            if (!header || !seg_name)
                return data;
            data.start = uintptr_t(getsegmentdata(header, seg_name, &data.size));
            data.end = data.start + data.size;
            return data;
        }

        inline seg_data_t getSection(const char *seg_name, const char *sect_name) const
        {
            seg_data_t data{};
            if (!header || !seg_name || !sect_name)
                return data;
            data.start = uintptr_t(getsectiondata(header, seg_name, sect_name, &data.size));
            data.end = data.start + data.size;
            return data;
        }
    };

    /*
     * Writes buffer content to an address
     */
    Memory_Status memWrite(void *address, const void *buffer, size_t len);

    /*
     * vm_region_recurse_64 wrapper
     */
    kern_return_t getPageInfo(vm_address_t region, vm_region_submap_short_info_64 *info_out);

    /*
     * returns base executable info
     */
    MemoryFileInfo getBaseInfo();

    /*
     * find in memory file info by checking if target loaded object file ends with @fileName
     */
    MemoryFileInfo getMemoryFileInfo(const std::string &fileName);

    /*
     * returns the absolue address of a relative offset of a file in memory or NULL as
     * fileName for base executable
     */
    uintptr_t getAbsoluteAddress(const char *fileName, uintptr_t address);

#endif

} // namespace KittyMemory

#ifdef __APPLE__

namespace KittyScanner
{
    uintptr_t findSymbol(const KittyMemory::MemoryFileInfo &info, const std::string &symbol);
    uintptr_t findSymbol(const std::string &lib, const std::string &symbol);
} // namespace KittyScanner

#endif // __APPLE__
