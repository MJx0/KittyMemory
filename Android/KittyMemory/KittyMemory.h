//
//  KittyMemory.hpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#pragma once

#include <stdio.h>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <vector>

#define _SYS_PAGE_SIZE_ (sysconf(_SC_PAGE_SIZE))

#define _PAGE_START_OF_(x) ((uintptr_t)x & ~(uintptr_t)(_SYS_PAGE_SIZE_ - 1))
#define _PAGE_END_OF_(x, len) (_PAGE_START_OF_((uintptr_t)x + len - 1))
#define _PAGE_LEN_OF_(x, len) (_PAGE_END_OF_(x, len) - _PAGE_START_OF_(x) + _SYS_PAGE_SIZE_)
#define _PAGE_OFFSET_OF_(x) ((uintptr_t)x - _PAGE_START_OF_(x))

#include <android/log.h>

#ifdef kITTYMEMORY_DEBUG
#define KITTY_LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "KittyMemory", __VA_ARGS__))
#else
#define KITTY_LOGD(...)
#endif

#define KITTY_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "KittyMemory", __VA_ARGS__))
#define KITTY_LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "KittyMemory", __VA_ARGS__))

namespace KittyMemory
{

    class ProcMap {
    public:
        unsigned long long startAddress;
        unsigned long long endAddress;
        size_t length;
        int protection;
        bool readable, writeable, executable, is_private, is_shared, is_ro, is_rw, is_rx;
        unsigned long long offset;
        std::string dev;
        unsigned long inode;
        std::string pathname;

        ProcMap() : startAddress(0), endAddress(0), length(0), protection(0),
		            readable(false), writeable(false), executable(false),
                    is_private(false), is_shared(false),
                    is_ro(false), is_rw(false), is_rx(false),
                    offset(0), inode(0) {}

        inline bool isValid() const { return (length > 0); }
        inline bool isUnknown() const { return pathname.empty(); }
    };

    /*
     * mprotect wrapper
     */
    int setAddressProtection(void *address, size_t length, int protection);

    /*
     * Writes buffer content to an address
     */
    bool memWrite(void *address, const void *buffer, size_t len);

    /*
     * Reads an address content into a buffer
     */
    bool memRead(void *buffer, const void *address, size_t len);

    /*
     * /proc/self/cmdline
     */
    std::string getProcessName();

    /*
     * Gets info of all maps in current process
     */
    std::vector<ProcMap> getAllMaps();

    /*
     * Gets info of all maps which contain "name" in current process
     */
    std::vector<ProcMap> getMapsByName(const std::string& name);

    /*
     * Gets map info of an address in self process
     */
    ProcMap getAddressMap(const void *address);

    /*
     * Gets the base map of a loaded shared object
     */
    ProcMap getBaseMapOf(const std::string& name);
}
