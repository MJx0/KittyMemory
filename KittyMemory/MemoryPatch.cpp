//
//  MemoryPatch.cpp
//
//  Created by MJ (Ruit) on 1/1/19.
//

#include "MemoryPatch.hpp"
#include "KittyUtils.hpp"

#ifndef kNO_KEYSTONE
#include "Deps/Keystone/includes/keystone.h"
#endif

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
  _orig_code.shrink_to_fit();

  _patch_code.clear();
  _patch_code.shrink_to_fit();
}

MemoryPatch MemoryPatch::createWithBytes(uintptr_t absolute_address, const void *patch_code, size_t patch_size)
{
  MemoryPatch patch;

  if (!absolute_address || !patch_code || patch_size < 1)
    return patch;

  patch._address = absolute_address;
  patch._size = patch_size;

  patch._orig_code.resize(patch_size);
  patch._patch_code.resize(patch_size);

  // initialize patch & backup current content
  KittyMemory::memRead(patch_code, &patch._patch_code[0], patch_size);
  KittyMemory::memRead(reinterpret_cast<const void *>(patch._address), &patch._orig_code[0], patch_size);
  return patch;
}

MemoryPatch MemoryPatch::createWithHex(uintptr_t absolute_address, std::string hex)
{
  MemoryPatch patch;

  if (!absolute_address || !KittyUtils::String::ValidateHex(hex))
    return patch;

  patch._address = absolute_address;
  patch._size = hex.length() / 2;

  patch._orig_code.resize(patch._size);
  patch._patch_code.resize(patch._size);

  // initialize patch
  KittyUtils::dataFromHex(hex, &patch._patch_code[0]);

  // backup current content
  KittyMemory::memRead(reinterpret_cast<const void *>(patch._address), &patch._orig_code[0], patch._size);
  return patch;
}

#ifndef kNO_KEYSTONE
MemoryPatch MemoryPatch::createWithAsm(uintptr_t absolute_address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address)
{
  MemoryPatch patch;

  if (!absolute_address || asm_code.empty())
      return patch;

  ks_engine *ks = nullptr;
  ks_err err = KS_ERR_ARCH;

  switch (asm_arch) {
    case MP_ASM_ARM32:
      err = ks_open(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, &ks);
      break;
    case MP_ASM_ARM64:
      err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
      break;
    case MP_ASM_x86:
      err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
      break;
    case MP_ASM_x86_64:
      err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
      break;
    default:
      KITTY_LOGE("Unknown MP_ASM_ARCH '%d'.", asm_arch);
      return patch;
  }

  if (err != KS_ERR_OK) {
    KITTY_LOGE("ks_open failed with error = '%s'.", ks_strerror(err));
    return patch;
  }

  unsigned char *insn_bytes = nullptr;
  size_t insn_count = 0, insn_size = 0;
  int rt = ks_asm(ks, asm_code.c_str(), asm_address, &insn_bytes, &insn_size, &insn_count);

  if (rt == 0 && insn_bytes != nullptr && insn_size) {
    patch = createWithBytes(absolute_address, insn_bytes, insn_size);
  }

  if (insn_bytes != nullptr) {
    ks_free(insn_bytes);
  }

  ks_close(ks);

  if (rt) {
    KITTY_LOGE("ks_asm failed (asm: %s, count = %zu, error = '%s') (code = %u).", asm_code.c_str(), insn_count, ks_strerror(ks_errno(ks)), ks_errno(ks));
  }

  return patch;
}
#endif // kNO_KEYSTONE

#ifdef __ANDROID__

MemoryPatch MemoryPatch::createWithBytes(const KittyMemory::ProcMap &map, uintptr_t address, const void *patch_code, size_t patch_size)
{
  if (!address || !map.startAddress || !map.isValid())
    return MemoryPatch();

  return createWithBytes(map.startAddress+address, patch_code, patch_size);
}

MemoryPatch MemoryPatch::createWithHex(const KittyMemory::ProcMap &map, uintptr_t address, const std::string &hex)
{
  if (!address || !map.startAddress || !map.isValid())
    return MemoryPatch();

  return createWithHex(map.startAddress+address, hex);
}

#elif __APPLE__

MemoryPatch MemoryPatch::createWithBytes(const char *fileName, uintptr_t address, const void *patch_code, size_t patch_size)
{
  if (!address || !patch_code || !patch_size)
    return MemoryPatch();

  uintptr_t absolute_address = KittyMemory::getAbsoluteAddress(fileName, address);
  return createWithBytes(absolute_address, patch_code, patch_size);
}

MemoryPatch MemoryPatch::createWithHex(const char *fileName, uintptr_t address, const std::string &hex)
{
  if (!address || hex.empty())
    return MemoryPatch();

  uintptr_t absolute_address = KittyMemory::getAbsoluteAddress(fileName, address);
  return createWithHex(absolute_address, hex);
}

#endif

#ifndef kNO_KEYSTONE

#ifdef __ANDROID__
MemoryPatch MemoryPatch::createWithAsm(const KittyMemory::ProcMap &map, uintptr_t address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address)
{
  if (!address || !map.startAddress || !map.isValid())
    return MemoryPatch();

  return createWithAsm(map.startAddress+address, asm_arch, asm_code, asm_address);
}

#elif __APPLE__
MemoryPatch MemoryPatch::createWithAsm(const char *fileName, uintptr_t address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address)
{
  if (!address || asm_code.empty())
    return MemoryPatch();

  uintptr_t absolute_address = KittyMemory::getAbsoluteAddress(fileName, address);
  return createWithAsm(absolute_address, asm_arch, asm_code, asm_address);
}
#endif

#endif // kNO_KEYSTONE

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

#ifdef __ANDROID__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size);
#elif __APPLE__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size) == KittyMemory::KMS_SUCCESS;
#endif
}

bool MemoryPatch::Modify()
{
  if (!isValid()) return false;

#ifdef __ANDROID__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_patch_code[0], _size);
#elif __APPLE__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_patch_code[0], _size) == KittyMemory::KMS_SUCCESS;
#endif
}

std::string MemoryPatch::get_CurrBytes() const
{
  if (!isValid()) return "";
  
  return KittyUtils::data2Hex(reinterpret_cast<const void *>(_address), _size);
}

std::string MemoryPatch::get_OrigBytes() const
{
  if (!isValid()) return "";
  
  return KittyUtils::data2Hex( _orig_code.data(), _orig_code.size());
}

std::string MemoryPatch::get_PatchBytes() const
{
  if (!isValid()) return "";
  
  return KittyUtils::data2Hex(_patch_code.data(), _patch_code.size());
}