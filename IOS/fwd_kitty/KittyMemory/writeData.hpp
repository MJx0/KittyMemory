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

#include <math.h>
#include "MemoryPatch.hpp"


#define BITS_IN_BYTE 8


// https://www.exploringbinary.com/number-of-bits-in-a-decimal-integer/
// returns bits size of an integer
inline int findBits(uint64_t n) 
{ 
   if(n > 0)
   {
	   return floor(log(n)/log(2))+1;
   }
   return 0;
} 


// returns bytes size of an integer
inline size_t findBytes(uint64_t data) 
{ 
   int bits = findBits(data);
   if(bits > 0)
   {
	   return (size_t)(bits / BITS_IN_BYTE);
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

bool writeData8 (uint64_t offset, uint8_t  data);
bool writeData16(uint64_t offset, uint16_t data);
bool writeData32(uint64_t offset, uint32_t data);
bool writeData64(uint64_t offset, uint64_t data);

#endif /* writeData.h */