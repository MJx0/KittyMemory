//
//  writeData.h
//
//
//  Created by MJ (Ruit) on 4/13/19.
//


/* 
   This is an alternative for the old writeData that was made by HackJack & Razzile 
*/


#ifndef writeData_h
#define writeData_h

#include "MemoryPatch.hpp"


#define BITS_IN_BYTE 8


// returns bits size of an integer
template<typename T>
size_t findBits(T data) 
{ 
   size_t bits = 0; 
   while (data) 
   { 
        bits++; 
        data >>= 1; 
   } 
   return bits; 
} 


// returns bytes size of an integer
template<typename T>
size_t findBytes(T data) 
{ 
   size_t bits = findBits(data);
   if(bits > 0)
   {
	   return bits / BITS_IN_BYTE;
   }
   return 0;
} 


template<typename T>
void SwapData(T& data) 
{
	const size_t sz = sizeof(T);
	switch (sz) 
	{
	   case sizeof(int16_t):
	       data = _OSSwapInt16(data);
	       break;
	   case sizeof(int32_t):
	       data = _OSSwapInt32(data);
	       break;
	   case sizeof(int64_t):
	       data = _OSSwapInt64(data);
	       break;
	   default:
	       break;
	}
}

bool writeData  (uint64_t offset, uint8_t  data);
bool writeData16(uint64_t offset, uint16_t data);
bool writeData32(uint64_t offset, uint32_t data);
bool writeData64(uint64_t offset, uint64_t data);

#endif /* writeData.h */