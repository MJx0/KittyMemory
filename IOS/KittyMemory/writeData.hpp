/*
   This is an alternative for the old writeData that was made by HackJack & Razzile
*/

#pragma once

#include <cmath>
#include <cstdint>

/*
 * expects file name and relative address, you can pass NULL as filename for base executable
 */
bool writeData8(const char *fileName, uintptr_t offset, uint8_t data);

/*
 * expects file name and relative address, you can pass NULL as filename for base executable
 */
bool writeData16(const char *fileName, uintptr_t offset, uint16_t data);

/*
 * expects file name and relative address, you can pass NULL as filename for base executable
 */
bool writeData32(const char *fileName, uintptr_t offset, uint32_t data);

/*
 * expects file name and relative address, you can pass NULL as filename for base executable
 */
bool writeData64(const char *fileName, uintptr_t offset, uint64_t data);