//
//  KittyMemory.hpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#ifndef KittyMemory_h
#define KittyMemory_h

#include <stdio.h>
#include <string>
#include <unistd.h>
#include <sys/mman.h>

#include "Logger.h"


#define _SYS_PAGE_SIZE_ (sysconf(_SC_PAGE_SIZE))

#define _PAGE_START_OF_(x)    ((uintptr_t)x & ~(uintptr_t)(_SYS_PAGE_SIZE_ - 1))
#define _PAGE_END_OF_(x, len) (_PAGE_START_OF_((uintptr_t)x + len - 1))
#define _PAGE_LEN_OF_(x, len) (_PAGE_END_OF_(x, len) - _PAGE_START_OF_(x) + _SYS_PAGE_SIZE_)
#define _PAGE_OFFSET_OF_(x)   ((uintptr_t)x - _START_PAGE_OF_(x))

#define _PROT_RWX_ (PROT_READ | PROT_WRITE | PROT_EXEC)
#define _PROT_RX_  (PROT_READ | PROT_EXEC)


namespace KittyMemory {

    typedef enum {
        FAILED = 0,
        SUCCESS = 1,
        INV_ADDR = 2,
        INV_LEN = 3,
        INV_BUF = 4,
        INV_PROT = 5
    } Memory_Status;

    /*
   * Changes protection of an address with given length
   */
    bool ProtectAddr(void *addr, size_t length, int protection);

    /*
    * Writes buffer content to an address
   */
    Memory_Status Write(void *addr, const void *buffer, size_t len);

    /*
   * Reads an address content into a buffer
   */
    Memory_Status Read(void *buffer, const void *addr, size_t len);

    /*
     * Reads an address content and returns hex string
     */
    std::string read2HexStr(const void *addr, size_t len);


    /*
     * Wrapper to dereference & read value of a pointer
     * Make sure to use the correct data type!
     */
    template<typename Type>
    Type readPointer(void *ptr) {
        Type defaultVal = {0};
        if (ptr == nullptr)
            return defaultVal;
        return *(Type *) ptr;
    }


    /*
     * Wrapper to dereference & set value of a pointer
     * Make sure to use the correct data type!
     */
    template<typename Type>
    void writePointer(void *ptr, Type val) {
        if (ptr != nullptr)
            *(Type *) ptr = val;
    }

    /*
     * Gets address of a mapped library in self process
     */
    uintptr_t getLibraryBase(const char *libName);

    /*
    * Expects a relative address in a library
    * Returns final absolute address
    */
    uintptr_t getAbsoluteAddress(const char *libName, uintptr_t relativeAddr);
};

#endif /* KittyMemory_h */
