//
//  MemoryBackup.h
//
//  Created by MJ (Ruit) on 4/19/20.
//

#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "KittyMemory.hpp"


class MemoryBackup
{
private:
    uintptr_t _address;
    size_t _size;

    std::vector<uint8_t> _orig_code;

public:
    MemoryBackup();
    ~MemoryBackup();

    static MemoryBackup createBackup(uintptr_t absolute_address, size_t backup_size);

#ifdef __ANDROID__
    static MemoryBackup createBackup(const KittyMemory::ProcMap &map, uintptr_t address, size_t backup_size);
#elif __APPLE__
    static MemoryBackup createBackup(const char *fileName, uintptr_t address, size_t backup_size);
#endif

    bool isValid() const;
    size_t get_BackupSize() const;
    uintptr_t get_TargetAddress() const;

    /*
     * Restores backup code
     */
    bool Restore();

    /*
     * Returns hex string of the current target address bytes
     */
    std::string get_CurrBytes() const;

    /*
     * Returns hex string of the original bytes
     */
    std::string get_OrigBytes() const;
};
