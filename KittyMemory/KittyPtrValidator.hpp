#pragma once

#include <algorithm>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifdef __APPLE__
#include <mach/mach.h>

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
            : start(s), end(e), readable(r), writable(w), executable(x) {}

        inline bool canMergeWith(const RegionInfo &other) const
        {
            return end == other.start && readable == other.readable &&
                   writable == other.writable && executable == other.executable;
        }
    };

    std::vector<RegionInfo> regions_;
    const mach_port_t task_ = mach_task_self();
    const size_t page_size_ = sysconf(_SC_PAGESIZE);
    bool use_cache_ = true;
    size_t last_region_index_ = 0;

    bool _findRegion(uintptr_t addr, RegionInfo *region);

public:
    KittyPtrValidator() : task_(mach_task_self()), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(true), last_region_index_(0) {}

    KittyPtrValidator(mach_port_t task, bool use_cache) : task_(task), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(use_cache), last_region_index_(0) {}

    inline void setUseCache(bool use_cache)
    {
        use_cache_ = use_cache;
        if (!use_cache_)
        {
            regions_.clear();
            last_region_index_ = 0;
        }
    }

    inline bool isPtrReadable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.readable;
    }

    inline bool isPtrWritable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.writable;
    }

    inline bool isPtrExecutable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.executable;
    }

    inline bool isPtrInAddressSpace(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region);
    }

    inline bool isPtrReadable(const void *ptr) { return ptr && isPtrReadable(uintptr_t(ptr)); }
    inline bool isPtrWritable(const void *ptr) { return ptr && isPtrWritable(uintptr_t(ptr)); }
    inline bool isPtrExecutable(const void *ptr) { return ptr && isPtrExecutable(uintptr_t(ptr)); }
    inline bool isPtrInAddressSpace(const void *ptr) { return ptr && isPtrInAddressSpace(uintptr_t(ptr)); }

    inline void clearCache()
    {
        regions_.clear();
        last_region_index_ = 0;
    }

    void refreshRegionCache();

    inline std::vector<RegionInfo> regions() const
    {
        return regions_;
    }
};

#else

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
            : start(s), end(e), readable(r), writable(w), executable(x) {}

        inline bool canMergeWith(const RegionInfo &other) const
        {
            return end == other.start && readable == other.readable &&
                   writable == other.writable && executable == other.executable;
        }
    };

    std::vector<RegionInfo> regions_;
    pid_t pid_ = getpid();
    const size_t page_size_ = sysconf(_SC_PAGESIZE);
    bool use_cache_ = true;
    size_t last_region_index_ = 0;

    std::string _readMapsFile();

    bool _parseMapsLine(const std::string &line, RegionInfo *region);

    void _parseMapsFromBuffer(const std::string &buffer, std::vector<RegionInfo> *output);

    bool _findRegion(uintptr_t addr, RegionInfo *region);

public:
    KittyPtrValidator() : pid_(getpid()), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(true), last_region_index_(0) {}

    KittyPtrValidator(pid_t pid, bool use_cache) : pid_(pid), page_size_(sysconf(_SC_PAGESIZE)), use_cache_(use_cache), last_region_index_(0) {}

    inline void setUseCache(bool use_cache)
    {
        use_cache_ = use_cache;
        if (!use_cache_)
        {
            regions_.clear();
            last_region_index_ = 0;
        }
    }

    inline void setPID(pid_t pid)
    {
        regions_.clear();
        last_region_index_ = 0;
        pid_ = pid;
    }

    inline bool isPtrReadable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.readable;
    }

    inline bool isPtrWritable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.writable;
    }

    inline bool isPtrExecutable(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region) && region.executable;
    }

    inline bool isPtrInAddressSpace(uintptr_t ptr)
    {
        if (ptr == 0) return false;
        RegionInfo region(0, 0, false, false, false);
        return _findRegion(ptr, &region);
    }

    inline bool isPtrReadable(const void *ptr) { return ptr && isPtrReadable(uintptr_t(ptr)); }
    inline bool isPtrWritable(const void *ptr) { return ptr && isPtrWritable(uintptr_t(ptr)); }
    inline bool isPtrExecutable(const void *ptr) { return ptr && isPtrExecutable(uintptr_t(ptr)); }
    inline bool isPtrInAddressSpace(const void *ptr) { return ptr && isPtrInAddressSpace(uintptr_t(ptr)); }

    inline void clearCache()
    {
        regions_.clear();
        last_region_index_ = 0;
    }

    void refreshRegionCache();

    inline std::vector<RegionInfo> regions() const
    {
        return regions_;
    }
};

#endif
