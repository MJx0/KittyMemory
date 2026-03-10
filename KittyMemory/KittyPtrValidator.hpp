#pragma once

#include <inttypes.h>
#include <algorithm>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <cstdio>
#include <cstdlib>

#include "KittyUtils.hpp"

#ifdef __APPLE__
#include <mach/mach.h>

/**
 * @brief Validates the memory access rights for a given address range.
 *
 * This class uses Mach kernel APIs to determine the read, write, and execute permissions of a memory address.
 */
class KittyPtrValidator
{
private:
    struct RegionInfo
    {
        uintptr_t start;
        uintptr_t end;
        bool readable;
        bool writable;
        bool executable;

        RegionInfo(uintptr_t s, uintptr_t e, bool r, bool w, bool x)
            : start(s), end(e), readable(r), writable(w), executable(x)
        {
        }

        inline bool canMergeWith(const RegionInfo &other) const
        {
            return end == other.start && readable == other.readable && writable == other.writable &&
                   executable == other.executable;
        }
    };

    std::vector<RegionInfo> cachedRegions_;
    const mach_port_t task_ = mach_task_self();
    const size_t page_size_ = sysconf(_SC_PAGESIZE);
    bool use_cache_ = true;
    size_t last_region_index_ = 0;

    bool _findRegion(uintptr_t addr, RegionInfo *region);

public:
    KittyPtrValidator()
        : task_(mach_task_self()), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(false), last_region_index_(0)
    {
    }

    /**
     * @brief Constructs a KittyPtrValidator object with the specified task and whether to use a cache.
     *
     * @param task process task.
     * @param use_cache Determines if the cache should be used.
     */
    KittyPtrValidator(mach_port_t task, bool use_cache)
        : task_(task), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(use_cache), last_region_index_(0)
    {
        if (use_cache_)
            refreshRegionCache();
    }

    /**
     * @brief Sets whether to use cached region information.
     *
     * @param use_cache True to use cached region information, false to clear the cache.
     */
    inline void setUseCache(bool use_cache)
    {
        use_cache_ = use_cache;
        if (!use_cache_)
        {
            cachedRegions_.clear();
            last_region_index_ = 0;
        }
        else
        {
            refreshRegionCache();
        }
    }

    /**
     * @brief Checks if a pointer is readable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is readable, false otherwise.
     */
    bool isPtrReadable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is writable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is writable, false otherwise.
     */
    bool isPtrWritable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is executable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is executable, false otherwise.
     */
    bool isPtrExecutable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is within the address space of the current task.
     *
     * @param ptr The memory address to check.
     * @return true if the pointer is within the address space, false otherwise.
     */
    inline bool isPtrInAddressSpace(uintptr_t ptr)
    {
        if (ptr == 0)
            return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region);
    }

    inline bool isPtrReadable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrReadable(uintptr_t(ptr), len);
    }
    inline bool isPtrWritable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrWritable(uintptr_t(ptr), len);
    }
    inline bool isPtrExecutable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrExecutable(uintptr_t(ptr), len);
    }
    inline bool isPtrInAddressSpace(const void *ptr)
    {
        return ptr && isPtrInAddressSpace(uintptr_t(ptr));
    }

    /**
     * @brief Clears the cached region information.
     */
    inline void clearCache()
    {
        cachedRegions_.clear();
        last_region_index_ = 0;
    }

    /**
     * @brief Refreshes the cached region information.
     */
    void refreshRegionCache();

    /**
     * @brief Retrieves the cached region information.
     *
     * @return A vector of RegionInfo objects representing the cached regions.
     */
    inline std::vector<RegionInfo> cachedRegions() const
    {
        return cachedRegions_;
    }
};

#else

/**
 * @brief Validates the memory access rights for a given address range.
 *
 * This class uses process maps to determine the read, write, and execute permissions of a memory address.
 */
class KittyPtrValidator
{
private:
    struct RegionInfo
    {
        uintptr_t start;
        uintptr_t end;
        bool readable;
        bool writable;
        bool executable;

        RegionInfo(uintptr_t s, uintptr_t e, bool r, bool w, bool x)
            : start(s), end(e), readable(r), writable(w), executable(x)
        {
        }

        inline bool canMergeWith(const RegionInfo &other) const
        {
            return end == other.start && readable == other.readable && writable == other.writable &&
                   executable == other.executable;
        }
    };

    std::vector<RegionInfo> cachedRegions_;
    pid_t pid_ = getpid();
    const size_t page_size_ = sysconf(_SC_PAGESIZE);
    bool use_cache_ = true;
    size_t last_region_index_ = 0;

    bool _parseMapsLine(const char *line, RegionInfo *region);

    bool _findRegion(uintptr_t addr, RegionInfo *region);

public:
    KittyPtrValidator() : pid_(getpid()), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(false), last_region_index_(0)
    {
    }

    /**
     * @brief Constructs a KittyPtrValidator object with the specified process ID and whether to use a cache.
     *
     * @param pid The process ID.
     * @param use_cache Determines if the cache should be used.
     */
    KittyPtrValidator(pid_t pid, bool use_cache)
        : pid_(pid), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(use_cache), last_region_index_(0)
    {
        if (use_cache_)
            refreshRegionCache();
    }

    /**
     * @brief Sets whether to use cached region information.
     *
     * @param use_cache True to use cached region information, false to clear the cache.
     */
    inline void setUseCache(bool use_cache)
    {
        use_cache_ = use_cache;
        if (!use_cache_)
        {
            cachedRegions_.clear();
            last_region_index_ = 0;
        }
        else
        {
            refreshRegionCache();
        }
    }

    /**
     * @brief Sets the process ID to query memory regions.
     *
     * @param pid The process ID to query.
     */
    inline void setPID(pid_t pid)
    {
        cachedRegions_.clear();
        last_region_index_ = 0;
        pid_ = pid;

        if (use_cache_)
        {
            refreshRegionCache();
        }
    }

    /**
     * @brief Checks if a pointer is readable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is readable, false otherwise.
     */
    bool isPtrReadable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is writable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is writable, false otherwise.
     */
    bool isPtrWritable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is executable.
     *
     * @param ptr The memory address to check.
     * @param len The length of the memory range to check.
     * @return true if the memory address is executable, false otherwise.
     */
    bool isPtrExecutable(uintptr_t ptr, size_t len = sizeof(void *));

    /**
     * @brief Checks if a pointer is within the address space of the current process.
     *
     * @param ptr The memory address to check.
     * @return true if the pointer is within the address space, false otherwise.
     */
    inline bool isPtrInAddressSpace(uintptr_t ptr)
    {
        if (ptr == 0)
            return false;
        ptr = KittyUtils::untagHeepPtr(ptr);
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region);
    }

    inline bool isPtrReadable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrReadable(uintptr_t(ptr), len);
    }
    inline bool isPtrWritable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrWritable(uintptr_t(ptr), len);
    }
    inline bool isPtrExecutable(const void *ptr, size_t len = sizeof(void *))
    {
        return ptr && isPtrExecutable(uintptr_t(ptr), len);
    }
    inline bool isPtrInAddressSpace(const void *ptr)
    {
        return ptr && isPtrInAddressSpace(uintptr_t(ptr));
    }

    /**
     * @brief Clears the cached region information.
     */
    inline void clearCache()
    {
        cachedRegions_.clear();
        last_region_index_ = 0;
    }

    /**
     * @brief Refreshes the cached region information.
     */
    void refreshRegionCache();

    /**
     * @brief Retrieves the cached region information.
     *
     * @return A vector of RegionInfo objects representing the cached regions.
     */
    inline std::vector<RegionInfo> cachedRegions() const
    {
        return cachedRegions_;
    }
};

#endif
