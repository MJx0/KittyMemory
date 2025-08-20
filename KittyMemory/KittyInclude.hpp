#pragma once

#include "KittyUtils.hpp"
#include "KittyMemory.hpp"
#include "MemoryPatch.hpp"
#include "KittyScanner.hpp"
#include "KittyAsm.hpp"
#include "KittyPtrValidator.hpp"
#include "KittyIOFile.hpp"

#ifdef __ANDROID__
using KittyMemory::ProcMap;
using KittyMemory::EProcMapFilter;
using KittyScanner::RegisterNativeFn;
using KittyScanner::ElfScanner;
using KittyScanner::LinkerScanner;
using KittyScanner::EScanElfType;
using KittyScanner::EScanElfFilter;
using KittyScanner::kitty_soinfo_t;
using KittyScanner::NativeBridgeScanner;
using KittyScanner::nbItf_data_t;
using KittyScanner::KT_JNICallType;
using KittyScanner::NativeBridgeLinker;

#elif __APPLE__
#include "writeData.hpp"
using KittyMemory::seg_data_t;
using KittyMemory::MemoryFileInfo;
#endif
