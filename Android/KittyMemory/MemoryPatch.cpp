//
//  MemoryPatch.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "MemoryPatch.h"
#include "KittyUtils.h"

MemoryPatch::MemoryPatch()
{
  _address = 0;
  _size = 0;
  _orig_code.clear();
  _patch_code.clear();
}

MemoryPatch::~MemoryPatch()
{
  // clean up
  _orig_code.clear();
  _patch_code.clear();
}

MemoryPatch::MemoryPatch(const ProcMap &map, uintptr_t address,
                         const void *patch_code, size_t patch_size)
{
  _address = 0;
  _size = 0;
  _orig_code.clear();
  _patch_code.clear();

  if (!map.isValid() || address == 0 || !patch_code || patch_size < 1)
    return;

  _address = map.startAddress+address;
  if (_address == 0)
    return;

  _size = patch_size;

  _orig_code.resize(patch_size);
  _patch_code.resize(patch_size);

  // initialize patch & backup current content
  KittyMemory::memRead(&_patch_code[0], patch_code, patch_size);
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), patch_size);
}

MemoryPatch::MemoryPatch(uintptr_t absolute_address,
                         const void *patch_code, size_t patch_size)
{
  _address = 0;
  _size = 0;
  _orig_code.clear();
  _patch_code.clear();

  if (absolute_address == 0 || !patch_code || patch_size < 1)
    return;

  _address = absolute_address;
  _size = patch_size;

  _orig_code.resize(patch_size);
  _patch_code.resize(patch_size);

  // initialize patch & backup current content
  KittyMemory::memRead(&_patch_code[0], patch_code, patch_size);
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), patch_size);
}

MemoryPatch MemoryPatch::createWithHex(const ProcMap &map, uintptr_t address,
                                       std::string hex)
{
  MemoryPatch patch;

  if (!map.isValid() || address == 0 || !KittyUtils::validateHexString(hex))
    return patch;

  patch._address = map.startAddress+address;
  if (patch._address == 0)
    return patch;

  patch._size = hex.length() / 2;

  patch._orig_code.resize(patch._size);
  patch._patch_code.resize(patch._size);

  // initialize patch
  KittyUtils::fromHex(hex, &patch._patch_code[0]);

  // backup current content
  KittyMemory::memRead(&patch._orig_code[0], reinterpret_cast<const void *>(patch._address), patch._size);
  return patch;
}

MemoryPatch MemoryPatch::createWithHex(uintptr_t absolute_address, std::string hex)
{
  MemoryPatch patch;

  if (absolute_address == 0 || !KittyUtils::validateHexString(hex))
    return patch;

  patch._address = absolute_address;
  patch._size = hex.length() / 2;

  patch._orig_code.resize(patch._size);
  patch._patch_code.resize(patch._size);

  // initialize patch
  KittyUtils::fromHex(hex, &patch._patch_code[0]);

  // backup current content
  KittyMemory::memRead(&patch._orig_code[0], reinterpret_cast<const void *>(patch._address), patch._size);
  return patch;
}

bool MemoryPatch::isValid() const
{
  return (_address != 0 && _size > 0 && _orig_code.size() == _size && _patch_code.size() == _size);
}

size_t MemoryPatch::get_PatchSize() const
{
  return _size;
}

uintptr_t MemoryPatch::get_TargetAddress() const
{
  return _address;
}

bool MemoryPatch::Restore()
{
  if (!isValid()) return false;

  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size);
}

bool MemoryPatch::Modify()
{
  if (!isValid()) return false;

  return (KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_patch_code[0], _size));
}

std::string MemoryPatch::get_CurrBytes() const
{
  if (!isValid()) return "";
  
  return KittyMemory::read2HexStr(reinterpret_cast<const void *>(_address), _size);
}

std::string MemoryPatch::get_OrigBytes() const
{
  if (!isValid()) return "";
  
  return KittyMemory::read2HexStr(_orig_code.data(), _orig_code.size());
}

std::string MemoryPatch::get_PatchBytes() const
{
  if (!isValid()) return "";
  
  return KittyMemory::read2HexStr(_patch_code.data(), _patch_code.size());
}
