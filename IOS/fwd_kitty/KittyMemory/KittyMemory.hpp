//
//  KittyMemory.hpp
//
//
//  Created by MJ (Ruit) on 1/1/19.
//
//

#ifndef KittyMemory_hpp
#define KittyMemory_hpp

#include <stdio.h>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <vector>

#define BAD_KERN_CALL(call) call != KERN_SUCCESS

#define _SYS_PAGE_SIZE_ (sysconf(_SC_PAGE_SIZE))

#define _PAGE_START_OF_(x)    ((uintptr_t)x & ~(uintptr_t)(_SYS_PAGE_SIZE_ - 1))
#define _PAGE_END_OF_(x, len) (_PAGE_START_OF_((uintptr_t)x + len - 1))
#define _PAGE_LEN_OF_(x, len) (_PAGE_END_OF_(x, len) - _PAGE_START_OF_(x) + _SYS_PAGE_SIZE_)
#define _PAGE_OFFSET_OF_(x)   ((uintptr_t)x - _PAGE_START_OF_(x))

#define _PROT_RWX_ (PROT_READ | PROT_WRITE | PROT_EXEC)
#define _PROT_RX_  (PROT_READ | PROT_EXEC)
#define _PROT_RW_  (PROT_READ | PROT_WRITE)


#define EMPTY_VEC_OFFSET std::vector<int>()


namespace KittyMemory {

    typedef enum {
        FAILED = 0,
        SUCCESS = 1,
        INV_ADDR = 2,
        INV_LEN = 3,
        INV_BUF = 4,
        INV_PROT = 5,
        INV_KERN_CALL = 6,
        INV_MAP = 7
    } Memory_Status;


    typedef struct {
        int index;
        const mach_header *header;
        const char *name;
        intptr_t address;
    } memory_file_info;


    /*
     * Changes protection of an address with given length
     */
    bool ProtectAddr(void *address, size_t length, int protection, bool aligned);

    /*
     * Writes buffer content to an address
     */
    Memory_Status memWrite(void *address, const void *buffer, size_t len);

    /*
     * Reads an address content into a buffer
     */
    Memory_Status memRead(void *buffer, const void *addr, size_t len);

    /*
     * Wrapper to dereference & get value of a multi level pointer
     * Make sure to use the correct data type!
     */
    template<typename Type>
    Type readMultiPtr(void *ptr, std::vector<int> offsets) {
        Type defaultVal = {};
        if (ptr == NULL)
            return defaultVal;

        uintptr_t finalPtr = reinterpret_cast<uintptr_t>(ptr);
        int offsetsSize = offsets.size();
        if (offsetsSize > 0) {
            for (int i = 0; finalPtr != 0 && i < offsetsSize; i++) {
                if (i == (offsetsSize - 1))
                    return *reinterpret_cast<Type *>(finalPtr + offsets[i]);

                finalPtr = *reinterpret_cast<uintptr_t *>(finalPtr + offsets[i]);
            }
        }

        if (finalPtr == 0)
            return defaultVal;

        return *reinterpret_cast<Type *>(finalPtr);
    }


    /*
     * Wrapper to dereference & set value of a multi level pointer
     * Make sure to use the correct data type!, const objects won't work
     */
    template<typename Type>
    bool writeMultiPtr(void *ptr, std::vector<int> offsets, Type val) {
        if (ptr == NULL)
            return false;

        uintptr_t finalPtr = reinterpret_cast<uintptr_t>(ptr);
        int offsetsSize = offsets.size();
        if (offsetsSize > 0) {
            for (int i = 0; finalPtr != 0 && i < offsetsSize; i++) {
                if (i == (offsetsSize - 1)) {
                    *reinterpret_cast<Type *>(finalPtr + offsets[i]) = val;
                    return true;
                }

                finalPtr = *reinterpret_cast<uintptr_t *>(finalPtr + offsets[i]);
            }
        }

        if (finalPtr == 0)
            return false;

        *reinterpret_cast<Type *>(finalPtr) = val;
        return true;
    }


	/*
     * Wrapper to dereference & get value of a pointer
     * Make sure to use the correct data type!
     */
    template<typename Type>
    Type readPtr(void *ptr) {
        Type defaultVal = {};
        if (ptr == NULL)
            return defaultVal;

        return *reinterpret_cast<Type *>(ptr);
    }


	/*
     * Wrapper to dereference & set value of a pointer
     * Make sure to use the correct data type!, const objects won't work
     */
    template<typename Type>
    bool writePtr(void *ptr, Type val) {
        if (ptr == NULL)
            return false;

        *reinterpret_cast<Type *>(ptr) = val;
        return true;
    }


    /*
     * Reads an address content and returns hex string
     */
    std::string read2HexStr(const void *address, size_t len);


    kern_return_t getPageInfo(void *page_start, vm_region_submap_short_info_64 *outInfo);

    /*
    * returns base executable info
    */
    memory_file_info getBaseInfo();

    /*
    * find in memory file info
    */
    memory_file_info getMemoryFileInfo(const char *fileName);

    /*
    * returns relative address of file in memory, NULL as fileName will return base executable
    */
    uint64_t getAbsoluteAddress(const char *fileName, uint64_t address);

};

#endif /* KittyMemory_hpp */
