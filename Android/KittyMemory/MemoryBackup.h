//
//  MemoryBackup.h
//
//  Created by MJ (Ruit) on 4/19/20.
//

#pragma once

#include <vector>

#include "KittyMemory.h"

using KittyMemory::ProcMap;

class MemoryBackup
{
private:
    uintptr_t _address;
    size_t _size;

    std::vector<uint8_t> _orig_code;

public:
    MemoryBackup();

    /*
     * expects library name and relative address
     */
    MemoryBackup(const ProcMap &map, uintptr_t address, size_t backup_size);

    /*
     * expects absolute address
     */
    MemoryBackup(uintptr_t absolute_address, size_t backup_size);

    ~MemoryBackup();

    /*
     * Validate patch
     */
    bool isValid() const;

    size_t get_BackupSize() const;

    /*
     * Returns pointer to the target address
     */
    uintptr_t get_TargetAddress() const;

    /*
     * Restores backup code
     */
    bool Restore();

    /*
     * Returns current target address bytes as hex string
     */
    std::string get_CurrBytes() const;

    std::string get_OrigBytes() const;
};
