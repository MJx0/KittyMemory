/*
   This is an alternative for the old writeData that was made by HackJack & Razzile
*/

#include "writeData.hpp"
#include "MemoryPatch.hpp"
#include <libkern/_OSByteOrder.h>

bool writeData8(const char *fileName, uintptr_t offset, uint8_t data)
{
	return MemoryPatch(fileName, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ 1).Modify();
}

bool writeData16(const char *fileName, uintptr_t offset, uint16_t data)
{
	data = _OSSwapInt16(data);
	return MemoryPatch(fileName, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ 2).Modify();
}

bool writeData32(const char *fileName, uintptr_t offset, uint32_t data)
{
	data = _OSSwapInt32(data);
	return MemoryPatch(fileName, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ 4).Modify();
}

bool writeData64(const char *fileName, uintptr_t offset, uint64_t data)
{
	data = _OSSwapInt64(data);
	return MemoryPatch(fileName, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ 8).Modify();
}
