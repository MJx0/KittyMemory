#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

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
        uint64_t inode;
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
            return isValid() && readable && length > 4 && memcmp((const void *)startAddress, "\177ELF", 4) == 0;
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
            return KittyUtils::String::fmt("%" PRIxPTR "-%" PRIxPTR " %c%c%c%c %" PRIxPTR " %s %" PRIu64 " %s",
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
     * @brief Retrieves memory maps that match the specified filter.
     *
     * @param filter Filter type to use.
     * @param name Name to filter by.
     * @param maps Vector of cached process maps (optional).
     * @return Vector of ProcMap objects that match the filter.
     */
    std::vector<ProcMap> getMaps(EProcMapFilter filter,
                                 const std::string &name,
                                 const std::vector<ProcMap> &maps = getAllMaps());

    /**
     * @brief Retrieves the map information for a specific address in the current process.
     *
     * @param address Address to search for.
     * @param maps Vector of cached process maps (optional).
     * @return ProcMap object representing the map for the address, or an invalid map if not found.
     */
    ProcMap getAddressMap(uintptr_t address, const std::vector<ProcMap> &maps = getAllMaps());

    /**
     * @brief Returns all contiguous mappings of a file.
     *
     * Finds all memory maps backed by the specified file and groups adjacent
     * maps into contiguous mappings. Two maps are considered contiguous
     * when both their virtual addresses and file offsets are contiguous.
     * Multiple independent mappings of the same file are returned as separate
     * groups.
     *
     * @param path File path to search for.
     * @param maps Vector of cached process maps (optional).
     * @return A vector where each element represents a contiguous file mapping
     *         as a sequence of its constituent memory maps.
     */
    std::vector<std::vector<ProcMap>> getFileMappings(const std::string &path,
                                                      const std::vector<ProcMap> &maps = getAllMaps());

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
    bool memExecWrite(uintptr_t address, const void *buffer, size_t len);

    /**
     * @brief Dumps memory range to a disk file.
     *
     * @param address Starting address of the memory range.
     * @param size Length of the memory range.
     * @param destination Path of the destination file.
     * @param maps Vector of cached process maps (optional).
     * @return True if the dump operation is successful, false otherwise.
     */
    bool dumpMemToDisk(uintptr_t address,
                       size_t size,
                       const std::string &destination,
                       const std::vector<ProcMap> &maps = getAllMaps());

    /**
     * @brief Dumps all mappings of a mapped file to disk.
     *
     * If the file has multiple mappings, each mapping is written to a separate
     * output file by appending an index to the destination filename.
     *
     * @param memFile Path of the mapped file to dump.
     * @param destination Destination file or directory path.
     * @param maps Vector of cached process maps (optional).
     * @return True if at least one mapping was successfully dumped, false otherwise.
     */
    bool dumpFileMappingsToDisk(const std::string &memFile,
                                const std::string &destination,
                                const std::vector<ProcMap> &maps = getAllMaps());

#elif __APPLE__

    /**
     * @brief Represents a memory range with address bounds and access permissions.
     *        Used for both Mach-O segments and sections.
     */
    struct mem_range_info_t
    {
        uintptr_t start, end, offset;
        size_t size;
        bool readable, writeable, executable;
        vm_prot_t protection, max_protection;
        std::string name;

        mem_range_info_t() : start(0), end(0), offset(0), size(0), readable(false), writeable(false), executable(false)
        {
        }

        inline bool operator==(const mem_range_info_t &other) const
        {
            return (start == other.start && end == other.end && offset == other.offset &&
                    protection == other.protection && max_protection == other.max_protection && name == other.name);
        }

        inline bool operator!=(const mem_range_info_t &other) const
        {
            return (start != other.start || end != other.end || offset != other.offset ||
                    protection != other.protection || max_protection != other.max_protection || name != other.name);
        }

        /** @brief Returns true if this range was found and has a non-zero start/end address and size. */
        inline bool isValid() const
        {
            return start != 0 && end != 0 && size != 0;
        }

        /**
         * @brief Checks if the region contains a specific address.
         *
         * @param address Address to check.
         * @return True if the address is within the region, false otherwise.
         */
        inline bool contains(uintptr_t address) const
        {
            return address >= start && address < end;
        }

        /**
         * @brief Converts the region info to a string representation.
         */
        inline std::string toString() const
        {
            return KittyUtils::String::fmt("0x%" PRIxPTR "-0x%" PRIxPTR " 0x%" PRIxPTR " (0x%" PRIx64 ") %c%c%c %s %s",
                                           start,
                                           end,
                                           offset,
                                           uint64_t(size),
                                           readable ? 'r' : '-',
                                           writeable ? 'w' : '-',
                                           executable ? 'x' : '-',
                                           protection & VM_PROT_COPY ? "(COW)" : "",
                                           name.c_str());
        }
    };

    /**
     * @brief Enumerates the filter types for finding memory regions.
     */
    enum class EMemRegionFilter
    {
        Equal,
        Contains,
        StartWith,
        EndWith,
        Regex
    };

    /**
     * @brief Enumerates all mapped virtual memory regions in the current process.
     *
     * This function iterates through the process's virtual address space starting
     * from address 0 up to the end of the addressable memory space. It automatically
     * traverses page table submaps to ensure all leaf memory regions are returned.
     *
     * @return std::vector<mem_range_info_t> A vector containing info structures for
     *                                        all currently mapped memory regions.
     */
    std::vector<mem_range_info_t> getAllRegions();

    /**
     * @brief Retrieves memory regions whose names match the specified filter.
     *
     * Searches the provided memory regions using the specified matching mode.
     * If @p regions is omitted, all mapped memory regions in the current process
     * are enumerated automatically.
     *
     * @param filter Matching mode to use.
     * @param name Name or regular expression to match.
     * @param regions Vector of cached memory regions (optional).
     * @return A vector containing all matching memory regions.
     */
    std::vector<mem_range_info_t> getRegions(EMemRegionFilter filter,
                                             const std::string &name,
                                             const std::vector<mem_range_info_t> &region = getAllRegions());

    /**
     * @brief Retrieves the region information for a specific address in the current process.
     *
     * @param address Address to check.
     * @param regions Vector of cached memory regions (optional).
     * @return mem_range_info_t object representing the region info for the address, or an invalid info if not found.
     */
    mem_range_info_t getAddressRegion(mach_vm_address_t address,
                                      const std::vector<mem_range_info_t> &region = getAllRegions());

    /**
     * @brief Returns all contiguous mappings of a file.
     *
     * Finds all memory regions backed by the specified file and groups adjacent
     * regions into contiguous mappings. Two regions are considered contiguous
     * when both their virtual addresses and file offsets are contiguous.
     * Multiple independent mappings of the same file are returned as separate
     * groups.
     *
     * @param path File path to search for.
     * @param regions Vector of cached memory regions (optional).
     * @return A vector where each element represents a contiguous file mapping
     *         as a sequence of its constituent memory regions.
     */
    std::vector<std::vector<mem_range_info_t>> getFileMappings(
        const std::string &path,
        const std::vector<mem_range_info_t> &regions = getAllRegions());

    /**
     * @brief Resolves a relative offset to an absolute address within a loaded image.
     *        Pass nullptr as imageName to resolve against the main executable.
     *
     * @param imageName Image name suffix to search for, or nullptr for the main executable.
     * @param address Relative offset within the image.
     * @return Absolute address, or 0 if the image was not found.
     */
    uintptr_t getAbsoluteAddress(const char *imageName, uintptr_t address);

    /**
     * @brief Dumps memory range to a disk file.
     *
     * @param address Starting address of the memory range.
     * @param size Length of the memory range.
     * @param destination Path of the destination file.
     * @param regions Vector of cached memory regions (optional).
     * @return True if the dump operation is successful, false otherwise.
     */
    bool dumpMemToDisk(uintptr_t address,
                       size_t size,
                       const std::string &destination,
                       const std::vector<mem_range_info_t> &regions = getAllRegions());

    /**
     * @brief Dumps all mappings of a mapped file to disk.
     *
     * If the file has multiple mappings, each mapping is written to a separate
     * output file by appending an index to the destination filename.
     *
     * @param memFile Path of the mapped file to dump.
     * @param destination Destination file or directory path.
     * @param regions Vector of cached memory regions (optional).
     * @return True if at least one mapping was successfully dumped, false otherwise.
     */
    bool dumpFileMappingsToDisk(const std::string &memFile,
                                const std::string &destination,
                                const std::vector<mem_range_info_t> &regions = getAllRegions());

#endif

    /**
     * @brief mprotect wrapper to modify the protection of a memory range.
     *
     * @param address Pointer to the start of the memory range.
     * @param length Length of the memory range.
     * @param protection New protection flags.
     * @return true on success, false on failure.
     */
    bool memProtect(uintptr_t address, size_t length, int protection);

    /**
     * @brief Reads an address content into a buffer.
     *
     * @param address Pointer to the address to read from.
     * @param buffer Pointer to the buffer where the read content will be stored.
     * @param len Number of bytes to read.
     * @return True if the read operation is successful, false otherwise.
     */
    bool memRead(uintptr_t address, void *buffer, size_t len);

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
    bool memWrite(uintptr_t address, const void *buffer, size_t len);

    /**
     * @brief Memory access strategy.
     *
     * Controls how memory read/write operations behave when encountering
     * inaccessible memory regions.
     */
    enum class MemMode
    {
        /**
         * @brief Perform a single continuous memory operation.
         *
         * The operation stops when the kernel reports an error or a partial
         * transfer occurs.
         */
        Normal,


        /**
         * @brief Continue operation while skipping inaccessible pages.
         *
         * The implementation will fall back to page-by-page access after a
         * failed continuous operation. Pages that cannot be accessed are skipped.
         */
        SkipInaccessiblePages
    };

    /**
     * @brief Performs a memory read operation using mach_vm_read_overwrite.
     *
     * @param address Starting address of the memory range.
     * @param buffer Pointer to the buffer for data transfer.
     * @param len Length of the data transfer.
     * @param mode Memory access strategy.
     * @return Number of bytes read.
     */
    size_t syscallMemRead(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);

    /**
     * @brief Performs a memory write operation using mach_vm_write.
     *
     * @param address Starting address of the memory range.
     * @param buffer Pointer to the buffer for data transfer.
     * @param len Length of the data transfer.
     * @param mode Memory access strategy.
     * @return Number of bytes written.
     */
    size_t syscallMemWrite(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);

} // namespace KittyMemory
