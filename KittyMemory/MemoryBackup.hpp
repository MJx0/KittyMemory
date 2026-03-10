#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "KittyMemory.hpp"


/**
 * @brief A class for backing up and restoring memory data.
 *
 * This class provides functionality to create a backup of a specific memory range,
 * restore the backup, and examine the current and original bytes of the memory.
 */
class MemoryBackup
{
private:
    uintptr_t _address;
    size_t _size;

    std::vector<uint8_t> _orig_code;

public:
    MemoryBackup();
    ~MemoryBackup();

    /**
     * @brief Creates a backup of the specified memory region.
     *
     * @param absolute_address The absolute address of the memory region to backup.
     * @param backup_size The size of the memory region to backup.
     * @return A new MemoryBackup object containing the backup data.
     */
    static MemoryBackup createBackup(uintptr_t absolute_address, size_t backup_size);

    /**
     * @brief Checks if the memory backup is valid.
     */
    bool isValid() const;
    /**
     * @brief Returns the size of the memory range that was backed up.
     */
    size_t get_BackupSize() const;

    /**
     * @brief Returns the address of the memory range that was backed up.
     */
    uintptr_t get_TargetAddress() const;

    /**
     * @brief Restores the backup code to the memory range.
     */
    bool Restore();

    /**
     * @brief Returns the hex string of the current target address bytes.
     */
    std::string get_CurrBytes() const;

    /**
     * @brief Returns the hex string of the original bytes of the memory range.
     */
    std::string get_OrigBytes() const;
};