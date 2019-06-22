//
//  writeData.cpp
//
//
//  Created by MJ (Ruit) on 4/13/19.
//


/*
   This is an alternative for the old writeData that was made by HackJack & Razzile
*/

#include "writeData.hpp"



bool writeData(uint64_t offset, uint8_t data)
{
	const size_t sz = sizeof(uint8_t);

	 // pass NULL as fileName for base executable
  return MemoryPatch(NULL, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ sz).Modify();
}

bool writeData16(uint64_t offset, uint16_t data)
{
	const size_t sz = sizeof(uint16_t);
	SwapData<uint16_t>(data);

	 // pass NULL as fileName for base executable
  return MemoryPatch(NULL, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ sz).Modify();
}

bool writeData32(uint64_t offset, uint32_t data)
{
	const size_t sz = sizeof(uint32_t);
	SwapData<uint32_t>(data);

	 // pass NULL as fileName for base executable
  return MemoryPatch(NULL, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ sz).Modify();
}


bool writeData64(uint64_t offset, uint64_t data)
{
	const size_t sz = sizeof(uint64_t);
	SwapData<uint64_t>(data);

	 // pass NULL as fileName for base executable
  return MemoryPatch(NULL, /* relative address */ offset, /* patch bytes */ &data, /* patch bytes length */ sz).Modify();
}
