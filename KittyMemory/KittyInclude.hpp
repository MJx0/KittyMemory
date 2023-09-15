#pragma once

#include "KittyUtils.hpp"
#include "KittyMemory.hpp"
#include "MemoryPatch.hpp"
#include "KittyScanner.hpp"
#include "KittyArm64.hpp"

#ifdef __ANDROID__
using KittyMemory::ProcMap;
using KittyScanner::RegisterNativeFn;

#elif __APPLE__
#include "writeData.hpp"
using KittyMemory::MemoryFileInfo;

#endif