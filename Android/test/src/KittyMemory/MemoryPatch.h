//
//  MemoryPatch.h
//
//  Created by MJ (Ruit) on 1/1/19.
//

#pragma once

#include <vector>

#include "KittyUtils.h"

#include "KittyMemory.h"
using KittyMemory::Memory_Status;
using KittyMemory::ProcMap;


class MemoryPatch {
private:
    uintptr_t _address;
    size_t    _size;

    std::vector<uint8_t> _orig_code;
    std::vector<uint8_t> _patch_code;

    std::string _hexString;

public:
    MemoryPatch();

    /*
     * expects library name and relative address
     */
    MemoryPatch(const char *libraryName, uintptr_t address,
            const void *patch_code, size_t patch_size, bool useMapCache=true);


    /*
     * expects absolute address
     */
    MemoryPatch(uintptr_t absolute_address, 
            const void *patch_code, size_t patch_size);


    ~MemoryPatch();

    /*
    * compatible hex format (0xffff & ffff & ff ff)
    */
    static MemoryPatch createWithHex(const char *libraryName, uintptr_t address, std::string hex, bool useMapCache=true);
    static MemoryPatch createWithHex(uintptr_t absolute_address, std::string hex);

    /*
     * Validate patch
     */
    bool isValid() const;


    size_t get_PatchSize() const;

    /*
     * Returns pointer to the target address
     */
    uintptr_t get_TargetAddress() const;


    /*
     * Restores patch to original value
     */
    bool Restore();


    /*
     * Applies patch modifications to target address
     */
    bool Modify();


    /*
     * Returns current patch target address bytes as hex string
     */
    std::string get_CurrBytes();
};
