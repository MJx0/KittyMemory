#pragma once

#include "KittyUtils.hpp"
#include "KittyMemory.hpp"
#include "MemoryPatch.hpp"
#include "KittyScanner.hpp"
#include "KittyArm64.hpp"

#ifdef __ANDROID__
using KittyMemory::ProcMap;
using KittyScanner::RegisterNativeFn;
using KittyScanner::ElfScanner;

#elif __APPLE__
#include "writeData.hpp"
using KittyMemory::seg_data_t;
using KittyMemory::MemoryFileInfo;
#endif