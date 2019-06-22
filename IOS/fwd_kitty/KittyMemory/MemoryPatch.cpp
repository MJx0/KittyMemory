//
//  MemoryPatch.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "MemoryPatch.hpp"


MemoryPatch::MemoryPatch() {
  _address = 0;
  _size    = 0;
  _orig_code.clear();
  _patch_code.clear();
}

MemoryPatch::MemoryPatch(uint64_t absolute_address,
                         const void *patch_code, size_t patch_size) {
    MemoryPatch();

    if (absolute_address == 0 || patch_code == NULL || patch_size < 1)
        return;

    _address = reinterpret_cast<void *>(absolute_address);

    if(_address == NULL)
        return;

    _size = patch_size;

    _orig_code.resize(patch_size);
    _patch_code.resize(patch_size);

    // initialize patch & backup current content
    KittyMemory::memRead(&_patch_code[0], patch_code, patch_size);
    KittyMemory::memRead(&_orig_code[0], static_cast<const void *>(_address), patch_size);
}

MemoryPatch::MemoryPatch(const char *fileName, uint64_t address,
                         const void *patch_code, size_t patch_size) {
    MemoryPatch();

    if (address == 0 || patch_code == NULL || patch_size < 1)
        return;

    _address = reinterpret_cast<void *>(KittyMemory::getAbsoluteAddress(fileName, address));

    if(_address == NULL)
        return;

    _size = patch_size;

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
    return (_address != NULL && _size > 0
            && _orig_code.size() == _size && _patch_code.size() == _size);
  }

  size_t MemoryPatch::get_PatchSize() const{
    return _size;
  }

  void *MemoryPatch::get_TargetAddress() const{
    return _address;
  }

  bool MemoryPatch::Restore() {
    if (!isValid()) return false;
    return KittyMemory::memWrite(_address, &_orig_code[0], _size) == KittyMemory::SUCCESS;
  }

  bool MemoryPatch::Modify() {
    if (!isValid()) return false;
    return (KittyMemory::memWrite(_address, &_patch_code[0], _size) ==  KittyMemory::SUCCESS);
  }

  std::string MemoryPatch::ToHexString() {
    if (!isValid()) return std::string("0xInvalid");
    return KittyMemory::read2HexStr(static_cast<const void *>(_address), _size);
  }
