//
//  MemoryPatch.h
//
//  Created by MJ (Ruit) on 1/1/19.
//

#pragma once

#include <vector>

#include "KittyMemory.hpp"
#include "KittyUtils.hpp"


class MemoryPatch {
private:
    void     *_address;
    size_t    _size;

    std::vector<uint8_t> _orig_code;
    std::vector<uint8_t> _patch_code;

    std::string _hexString;

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
    * compatible hex format (0xffff & ffff & ff ff)
    */
    static MemoryPatch createWithHex(const char *fileName, uint64_t address, std::string hex);
    static MemoryPatch createWithHex(uint64_t absolute_address, std::string hex);

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
    std::string get_CurrBytes();
};