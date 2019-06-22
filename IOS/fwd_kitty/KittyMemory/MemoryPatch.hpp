//
//  MemoryPatch.h
//
//  Created by MJ (Ruit) on 1/1/19.
//

#ifndef MemoryPatch_h
#define MemoryPatch_h

#include <vector>

#include "KittyMemory.hpp"


class MemoryPatch {
private:
    void     *_address;
    size_t    _size;

    std::vector<uint8_t> _orig_code;
    std::vector<uint8_t> _patch_code;

public:
    MemoryPatch();

    /*
     * expects an already calculated address
     */
    MemoryPatch(uint64_t absolute_address,
                             const void *patch_code, size_t patch_size);

    /*
     * expects file name and relative address, you can pass NULL as filename for base executable
     */
    MemoryPatch(const char *fileName, uint64_t address,
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
    void *get_TargetAddress() const;


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
