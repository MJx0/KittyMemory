/*
   This is an alternative for the old writeData that was made by HackJack & Razzile
*/

#pragma once

#ifdef __APPLE__

#include <cmath>
#include <cstdint>

#include "MemoryPatch.hpp"
#include <libkern/_OSByteOrder.h>

/*
 * expects file name and relative offset, you can pass NULL as filename for base executable
 */
static inline bool writeData8(const char *fileName, uintptr_t offset, uint8_t data)
{
   return MemoryPatch::createWithBytes(fileName, offset, &data, 1).Modify();
}

static inline bool writeData8(uintptr_t address, uint8_t data)
{
   return MemoryPatch::createWithBytes(address, &data, 1).Modify();
}

/*
 * expects file name and relative offset, you can pass NULL as filename for base executable
 */
static inline bool writeData16(const char *fileName, uintptr_t offset, uint16_t data)
{
   uint16_t tmp_data = _OSSwapInt16(data);
   return MemoryPatch::createWithBytes(fileName, offset, &tmp_data, 2).Modify();
}

static inline bool writeData16(uintptr_t address, uint16_t data)
{
   uint16_t tmp_data = _OSSwapInt16(data);
   return MemoryPatch::createWithBytes(address, &tmp_data, 2).Modify();
}

/*
 * expects file name and relative offset, you can pass NULL as filename for base executable
 */
static inline bool writeData32(const char *fileName, uintptr_t offset, uint32_t data)
{
   uint32_t tmp_data = _OSSwapInt32(data);
   return MemoryPatch::createWithBytes(fileName, offset, &tmp_data, 4).Modify();
}

static inline bool writeData32(uintptr_t address, uint32_t data)
{
   uint32_t tmp_data = _OSSwapInt32(data);
   return MemoryPatch::createWithBytes(address, &tmp_data, 4).Modify();
}

/*
 * expects file name and relative offset, you can pass NULL as filename for base executable
 */
static inline bool writeData64(const char *fileName, uintptr_t offset, uint64_t data)
{
   uint64_t tmp_data = _OSSwapInt64(data);
   return MemoryPatch::createWithBytes(fileName, offset, &tmp_data, 8).Modify();
}

static inline bool writeData64(uintptr_t address, uint64_t data)
{
   uint64_t tmp_data = _OSSwapInt64(data);
   return MemoryPatch::createWithBytes(address, &tmp_data, 8).Modify();
}

#endif