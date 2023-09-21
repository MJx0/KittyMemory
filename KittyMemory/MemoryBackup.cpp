//
//  MemoryBackup.cpp
//
//  Created by MJ (Ruit) on 4/19/20.
//

#include "MemoryBackup.hpp"
#include "KittyUtils.hpp"


MemoryBackup::MemoryBackup()
{
  _address = 0;
  _size = 0;
  _orig_code.clear();
}

MemoryBackup::~MemoryBackup()
{
  // clean up
  _orig_code.clear();
  _orig_code.shrink_to_fit();
}


MemoryBackup MemoryBackup::createBackup(uintptr_t absolute_address, size_t backup_size)
{
  MemoryBackup backup;

  if (!absolute_address || !backup_size) return backup;

  backup._address = absolute_address;

  backup._size = backup_size;

  backup._orig_code.resize(backup_size);

  // backup current content
  KittyMemory::memRead(reinterpret_cast<const void *>(backup._address), &backup._orig_code[0], backup_size);

  return backup;
}

#ifdef __ANDROID__
MemoryBackup MemoryBackup::createBackup(const KittyMemory::ProcMap &map, uintptr_t address, size_t backup_size)
{
  if (!map.isValid() || !address || !backup_size)
    return MemoryBackup();

  return createBackup(map.startAddress + address, backup_size);
}

#elif __APPLE__
MemoryBackup MemoryBackup::createBackup(const char *fileName, uintptr_t address, size_t backup_size)
{
  if (!address || !backup_size)
    return MemoryBackup();

  return createBackup(KittyMemory::getAbsoluteAddress(fileName, address), backup_size);
}
#endif

bool MemoryBackup::isValid() const
{
  return (_address != 0 && _size > 0 && _orig_code.size() == _size);
}

size_t MemoryBackup::get_BackupSize() const
{
  return _size;
}

uintptr_t MemoryBackup::get_TargetAddress() const
{
  return _address;
}

bool MemoryBackup::Restore()
{
  if (!isValid()) return false;

#ifdef __ANDROID__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size);
#elif __APPLE__
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size) == KittyMemory::KMS_SUCCESS;
#endif
}

std::string MemoryBackup::get_CurrBytes() const
{
  if (!isValid()) return "";
  
  return KittyUtils::data2Hex(reinterpret_cast<const void *>(_address), _size);
}

std::string MemoryBackup::get_OrigBytes() const
{
  if (!isValid()) return "";
  
  return KittyUtils::data2Hex(_orig_code.data(), _orig_code.size());
}