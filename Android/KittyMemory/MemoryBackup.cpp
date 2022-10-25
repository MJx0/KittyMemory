//
//  MemoryBackup.cpp
//
//  Created by MJ (Ruit) on 4/19/20.
//

#include "MemoryBackup.h"


MemoryBackup::MemoryBackup()
{
  _address = 0;
  _size = 0;
  _orig_code.clear();
}

MemoryBackup::MemoryBackup(const ProcMap &map, uintptr_t address, size_t backup_size)
{
  _address = 0;
  _size = 0;
  _orig_code.clear();

  if (!map.isValid() || address == 0 || backup_size < 1)
    return;

  _address = map.startAddress+address;
  if (_address == 0)
    return;

  _size = backup_size;

  _orig_code.resize(backup_size);

  // backup current content
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), backup_size);
}

MemoryBackup::MemoryBackup(uintptr_t absolute_address, size_t backup_size)
{
  _address = 0;
  _size = 0;
  _orig_code.clear();

  if (absolute_address == 0 || backup_size < 1)
    return;

  _address = absolute_address;

  _size = backup_size;

  _orig_code.resize(backup_size);

  // backup current content
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), backup_size);
}

MemoryBackup::~MemoryBackup()
{
  // clean up
  _orig_code.clear();
}

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
  
  return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size);
}

std::string MemoryBackup::get_CurrBytes() const
{
  if (!isValid()) return "";
  
  return KittyMemory::read2HexStr(reinterpret_cast<const void *>(_address), _size);
}

std::string MemoryBackup::get_OrigBytes() const
{
  if (!isValid()) return "";
  
  return KittyMemory::read2HexStr(_orig_code.data(), _orig_code.size());
}
