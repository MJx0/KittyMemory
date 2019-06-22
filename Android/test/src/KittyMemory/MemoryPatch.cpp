//
//  MemoryPatch.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "MemoryPatch.h"


MemoryPatch::MemoryPatch() {
  _address = 0;
  _size    = 0;
  _orig_code.clear();
  _patch_code.clear();
}

MemoryPatch::MemoryPatch(const char *libraryName, uintptr_t address, const void *patch_code, size_t patch_size) {
  MemoryPatch();

  if (libraryName == NULL || address == 0 || patch_code == NULL || patch_size < 1)
    return;

  _address = KittyMemory::getAbsoluteAddress(libraryName, address);
  if(_address == 0) return;
  
  _size    = patch_size;

  _orig_code.resize(patch_size);
  _patch_code.resize(patch_size);

  // initialize patch & backup current content
  KittyMemory::memRead(&_patch_code[0], patch_code, patch_size);
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), patch_size);
}

   MemoryPatch::~MemoryPatch() {
     // clean up
     _orig_code.clear();
     _patch_code.clear();
   }

  bool MemoryPatch::isValid() const {
    return (_address != 0 && _size > 0
            && _orig_code.size() == _size && _patch_code.size() == _size);
  }

  size_t MemoryPatch::get_PatchSize() const{
    return _size;
  }

  uintptr_t MemoryPatch::get_TargetAddress() const{
    return _address;
  }

  bool MemoryPatch::Restore() {
    if (!isValid()) return false;
    return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size) == Memory_Status::SUCCESS;
  }

  bool MemoryPatch::Modify() {
    if (!isValid()) return false;
    return (KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_patch_code[0], _size) == Memory_Status::SUCCESS);
  }

  std::string MemoryPatch::ToHexString() {
    if (!isValid()) return std::string("0xInvalid");
    return KittyMemory::read2HexStr(reinterpret_cast<const void *>(_address), _size);
  }
