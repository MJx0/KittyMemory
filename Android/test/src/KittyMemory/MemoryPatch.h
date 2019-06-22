//
//  MemoryPatch.h
//
//  Created by MJ (Ruit) on 1/1/19.
//

#ifndef MemoryPatch_h
#define MemoryPatch_h

#include <vector>

#include "KittyMemory.h"
using KittyMemory::Memory_Status;
using KittyMemory::ProcMap;


class MemoryPatch {
private:
    uintptr_t _address;
    size_t    _size;

    std::vector<uint8_t> _orig_code;
    std::vector<uint8_t> _patch_code;

public:
    MemoryPatch();

    /*
     * expects library name and relative address
     */
    MemoryPatch(const char *libraryName, uintptr_t address,
            const void *patch_code, size_t patch_size);


    ~MemoryPatch();

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
    std::string ToHexString();
};

#endif /* MemoryPatch_h */
