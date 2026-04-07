#pragma once

#include <inttypes.h>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <regex.h>
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

/**
 * @brief Provides utility functions for memory.
 */
namespace KittyMemory
{
    /**
     * @brief Reads an address content into a buffer.
     *
     * @param address Pointer to the address to read from.
     * @param buffer Pointer to the buffer where the read content will be stored.
     * @param len Number of bytes to read.
     * @return True if the read operation is successful, false otherwise.
     */
    bool memRead(const void *address, void *buffer, size_t len);

#ifdef __ANDROID__

    /**
     * @brief Represents a mapping of a memory region.
     */
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

        inline bool operator==(const ProcMap &other) const
        {
            return (startAddress == other.startAddress && endAddress == other.endAddress &&
                    protection == other.protection && is_private == other.is_private && is_shared == other.is_shared &&
                    offset == other.offset && dev == other.dev && inode == other.inode && pathname == other.pathname);
        }

        inline bool operator!=(const ProcMap &other) const
        {
            return (startAddress != other.startAddress || endAddress != other.endAddress ||
                    protection != other.protection || is_private != other.is_private || is_shared != other.is_shared ||
                    offset != other.offset || dev != other.dev || inode != other.inode || pathname != other.pathname);
        }

        /**
         * @brief Checks if the map is valid.
         */
        inline bool isValid() const
        {
            return (startAddress && endAddress && length);
        }

        /**
         * @brief Checks if the map is unknown (i.e., no pathname).
         */
        inline bool isUnknown() const
        {
            return pathname.empty();
        }

        /**
         * @brief Checks if the map is a valid ELF file.
         */
        inline bool isValidELF() const
        {
            return isValid() && length > 4 && memcmp((const void *)startAddress, "\177ELF", 4) == 0;
        }

        /**
         * @brief Checks if the map contains a specific address.
         *
         * @param address Address to check.
         * @return True if the address is within the map, false otherwise.
         */
        inline bool contains(uintptr_t address) const
        {
            return address >= startAddress && address < endAddress;
        }

        /**
         * @brief Converts the map to a string representation.
         */
        inline std::string toString() const
        {
            return KittyUtils::String::fmt("%" PRIxPTR "-%" PRIxPTR " %c%c%c%c %" PRIxPTR " %s %lu %s",
                                           startAddress,
                                           endAddress,
                                           readable ? 'r' : '-',
                                           writeable ? 'w' : '-',
                                           executable ? 'x' : '-',
                                           is_private ? 'p' : 's',
                                           offset,
                                           dev.c_str(),
                                           inode,
                                           pathname.c_str());
        }
    };

    /**
     * @brief Enumerates the filter types for finding memory maps.
     */
    enum class EProcMapFilter
    {
        Equal,
        Contains,
        StartWith,
        EndWith,
        Regex
    };

    /**
     * @brief mprotect wrapper to modify the protection of a memory range.
     *
     * @param address Pointer to the start of the memory range.
     * @param length Length of the memory range.
     * @param protection New protection flags.
     * @return 0 on success, -1 on failure.
     */
    int memProtect(const void *address, size_t length, int protection);

    /**
     * @brief Writes buffer content to an address.
     *
     * @param address Pointer to the address to write to.
     * @param buffer Pointer to the buffer containing the data to write.
     * @param len Number of bytes to write.
     * @return True if the write operation is successful, false otherwise.
     *
     * @note This function shouldn't be used on executable memory,
     * use @ref memExecWrite(void *, const void *, size_t) @endlink instead.
     */
    bool memWrite(void *address, const void *buffer, size_t len);

    /**
     * @brief Writes buffer content to an excutable address.
     *
     * @param address Pointer to the address to write to.
     * @param buffer Pointer to the buffer containing the data to write.
     * @param len Number of bytes to write.
     * @return True if the write operation is successful, false otherwise.
     *
     @note Adding write permission on executable memory is not enough on emulators,
     *  this is why this function exists which will add exec permission too.
     */
    bool memExecWrite(void *address, const void *buffer, size_t len);

    /**
     * @brief Reads /proc/self/cmdline to get the name of the current process.
     *
     * @return Name of the current process.
     */
    std::string getProcessName();

    /**
     * @brief Retrieves information about all memory maps in the current process.
     *
     * @return Vector of ProcMap objects representing all memory maps.
     */
    std::vector<ProcMap> getAllMaps();

    /**
     * @brief Retrieves memory maps that match a specified filter.
     *
     * @param filter Filter type to use.
     * @param name Name to filter by.
     * @param maps The vector of cached process maps (optional).
     * @return Vector of ProcMap objects that match the filter.
     */
    std::vector<ProcMap> getMaps(EProcMapFilter filter,
                                 const std::string &name,
                                 const std::vector<ProcMap> &maps = getAllMaps());

    /**
     * @brief Retrieves the map information for a specific address in the current process.
     *
     * @param address Address to search for.
     * @param maps The vector of cached process maps (optional).
     * @return ProcMap object representing the map for the address, or an invalid map if not found.
     */
    ProcMap getAddressMap(const void *address, const std::vector<ProcMap> &maps = getAllMaps());
    inline ProcMap getAddressMap(uintptr_t address, const std::vector<ProcMap> &maps = getAllMaps())
    {
        return getAddressMap((const void *)address, maps);
    }

    /**
     * @brief Dumps memory range to a disk file.
     *
     * @param address Starting address of the memory range.
     * @param size Length of the memory range.
     * @param destination Path of the destination file.
     * @return True if the dump operation is successful, false otherwise.
     */
    bool dumpMemToDisk(uintptr_t address, size_t size, const std::string &destination);

    /**
     * @brief Dumps memory mapped file to a disk file.
     *
     * @param memFile Name of the memory file to dump.
     * @param destination Path of the destination file.
     * @return True if the dump operation is successful, false otherwise.
     */
    bool dumpMemFileToDisk(const std::string &memFile, const std::string &destination);

    enum class EPROCESS_VM_OP
    {
        READV,
        WRITEV
    };

    size_t syscallMemOp(EPROCESS_VM_OP op, uintptr_t address, void *buffer, size_t len);

    /**
     * @brief Performs a memory read operation using process_vm_readv.
     *
     * @param address Starting address of the memory range.
     * @param buffer Pointer to the buffer for data transfer.
     * @param len Length of the data transfer.
     * @return Number of bytes transferred.
     */
    inline size_t syscallMemRead(uintptr_t address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::READV, address, buffer, len);
    }
    inline size_t syscallMemRead(void *address, void *buffer, size_t len)
    {
        return syscallMemOp(EPROCESS_VM_OP::READV, uintptr_t(address), buffer, len);
    }

    /**
     * @brief Performs a memory write operation using process_vm_writev.
     *
     * @param address Starting address of the memory range.
     * @param buffer Pointer to the buffer for data transfer.
     * @param len Length of the data transfer.
     * @return Number of bytes transferred.
     */
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

    /**
     * @brief Data structure for segment information.
     */
    struct seg_data_t
    {
        uintptr_t start, end;
        unsigned long size;
        seg_data_t() : start(0), end(0), size(0)
        {
        }
    };

    /**
     * @brief Represents a memory file information.
     */
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

        /**
         * @brief Retrieves the segment data by name.
         *
         * @param seg_name Segment name.
         * @return seg_data_t containing segment start, end, and size.
         */
        inline seg_data_t getSegment(const char *seg_name) const
        {
            seg_data_t data{};
            if (!header || !seg_name)
                return data;
            data.start = uintptr_t(getsegmentdata(header, seg_name, &data.size));
            data.end = data.start + data.size;
            return data;
        }

        /**
         * @brief Retrieves the section data by name.
         *
         * @param seg_name Segment name.
         * @param sect_name Section name.
         * @return seg_data_t containing section start, end, and size.
         */
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

    /**
     * @brief Writes buffer content to an address.
     *
     * @param address Pointer to the address to write to.
     * @param buffer Pointer to the buffer containing the data to write.
     * @param len Length of the data to write.
     * @return Memory_Status indicating the success or failure of the write operation.
     */
    Memory_Status memWrite(void *address, const void *buffer, size_t len);

    /**
     * @brief Retrieves page information using vm_region_recurse_64.
     *
     * @param region Region address.
     * @param info_out Pointer to store the region information.
     * @return kern_return_t indicating the success or failure of the operation.
     */
    kern_return_t getPageInfo(vm_address_t region, vm_region_submap_short_info_64 *info_out);

    /**
     * @brief Retrieves the base executable information.
     *
     * @return MemoryFileInfo object containing the base executable information.
     */
    MemoryFileInfo getBaseInfo();

    /**
     * @brief Finds a memory file info by checking if the target loaded object file ends with @fileName.
     *
     * @param fileName Name of the target loaded object file.
     * @return MemoryFileInfo object containing the memory file information, or an invalid object if not found.
     */
    MemoryFileInfo getMemoryFileInfo(const std::string &fileName);

    /**
     * @brief Retrieves the absolute address of a relative offset of a file in memory or NULL as fileName for base executable.
     *
     * @param fileName Name of the target file.
     * @param address Relative offset address.
     * @return The absolute address, or 0 if not found.
     */
    uintptr_t getAbsoluteAddress(const char *fileName, uintptr_t address);

#endif

} // namespace KittyMemory

#ifdef __APPLE__

namespace KittyScanner
{
    /**
     * @brief Finds a symbol in a memory file info based on the library and symbol name.
     *
     * @param info MemoryFileInfo object containing the memory file information.
     * @param symbol Symbol name to find.
     * @return uintptr_t representing the address of the symbol, or 0 if not found.
     */
    uintptr_t findSymbol(const KittyMemory::MemoryFileInfo &info, const std::string &symbol);

    /**
     * @brief Finds a symbol in a library based on the library and symbol name.
     *
     * @param lib Name of the library.
     * @param symbol Symbol name to find.
     * @return uintptr_t representing the address of the symbol, or 0 if not found.
     */
    uintptr_t findSymbol(const std::string &lib, const std::string &symbol);
} // namespace KittyScanner

#endif // __APPLE__
