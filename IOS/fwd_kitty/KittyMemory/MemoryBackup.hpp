//
//  MemoryBackup.hpp
//
//  Created by MJ (Ruit) on 4/19/20.
//

#pragma once

#include <vector>

#include "KittyMemory.hpp"

class MemoryBackup {
private:
    void     *_address;
    size_t    _size;

    std::vector<uint8_t> _orig_code;

    std::string _hexString;

public:
    MemoryBackup();

    /*
     * expects library name and relative address
     */
    MemoryBackup(const char *fileName, uint64_t address, size_t backup_size);

    /*
     * expects absolute address
     */
    MemoryBackup(uint64_t absolute_address, size_t backup_size);


    ~MemoryBackup();


    /*
     * Validate patch
     */
    bool isValid() const;


    size_t get_BackupSize() const;

    /*
     * Returns pointer to the target address
     */
    void *get_TargetAddress() const;


    /*
     * Restores backup code
     */
    bool Restore();


    /*
     * Returns current target address bytes as hex string
     */
    std::string get_CurrBytes();
};
