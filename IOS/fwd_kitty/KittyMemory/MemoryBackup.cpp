//
//  MemoryBackup.cpp
//
//  Created by MJ (Ruit) on 4/19/20.
//

#include "MemoryBackup.hpp"


MemoryBackup::MemoryBackup() {
  _address = 0;
  _size    = 0;
  _orig_code.clear();
}

MemoryBackup::MemoryBackup(const char *fileName, uint64_t address, size_t backup_size) {
  MemoryBackup();

  if (address == 0 || backup_size < 1)
    return;

   _address = reinterpret_cast<void *>(KittyMemory::getAbsoluteAddress(fileName, address));
   if(_address == NULL) return;
  
  _size = backup_size;

  _orig_code.resize(backup_size);

  // backup current content
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), backup_size);
}


MemoryBackup::MemoryBackup(uint64_t absolute_address, size_t backup_size) {
  MemoryBackup();

  if (absolute_address == 0 || backup_size < 1)
    return;

   _address = reinterpret_cast<void *>(absolute_address);
  
  _size = backup_size;

  _orig_code.resize(backup_size);

  // backup current content
  KittyMemory::memRead(&_orig_code[0], reinterpret_cast<const void *>(_address), backup_size);
}

   MemoryBackup::~MemoryBackup() {
     // clean up
     _orig_code.clear();
   }


  bool MemoryBackup::isValid() const {
    return (_address != 0 && _size > 0
            && _orig_code.size() == _size);
  }

  size_t MemoryBackup::get_BackupSize() const{
    return _size;
  }

  void *MemoryBackup::get_TargetAddress() const{
    return _address;
  }

  bool MemoryBackup::Restore() {
    if (!isValid()) return false;
    return KittyMemory::memWrite(reinterpret_cast<void *>(_address), &_orig_code[0], _size) == KittyMemory::SUCCESS;
  }

  std::string MemoryBackup::get_CurrBytes() {
    if (!isValid()) 
      _hexString = std::string("0xInvalid");
      else 
      _hexString = KittyMemory::read2HexStr(reinterpret_cast<const void *>(_address), _size);

    return _hexString;
  }
