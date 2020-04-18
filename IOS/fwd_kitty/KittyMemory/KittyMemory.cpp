//
//  KittyMemory.cpp
//
//
//  Created by MJ (Ruit) on 1/1/19.
//
//

#include "KittyMemory.hpp"
#include <substrate.h>


using KittyMemory::Memory_Status;


// may not be accurate
static bool cydiaExist(){
  bool ret = false;
  FILE *f = NULL;
  if(( f = fopen( "/Applications/Cydia.app" , "r" ) ) 
  || ( f = fopen( "/Library/MobileSubstrate/MobileSubstrate.dylib" , "r" ) )){
      ret = true;
  }
  if(f != NULL){
    fclose(f);
  }
  return ret;
}

typedef void (*MSHookMemory_t)(void *, const void *, size_t);
inline bool findMSHookMemory(void *dst, const void *src, size_t len){
  static void *ret = MSFindSymbol(NULL, "_MSHookMemory");
  if(ret != NULL){
    reinterpret_cast<MSHookMemory_t>(ret)(dst, src, len);
    return true;
  }
  return false;
}


extern "C" kern_return_t mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
                                  mach_vm_offset_t, int, vm_map_t, mach_vm_address_t,
                                  boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);


bool KittyMemory::ProtectAddr(void *address, size_t length, int protection, bool aligned) {
    if(aligned)
        return mprotect(address, length, protection) != -1;

    uintptr_t pageStart = _PAGE_START_OF_(address);
    uintptr_t pageLen   = _PAGE_LEN_OF_(address, length);
    return mprotect(reinterpret_cast<void *>(pageStart), pageLen, protection) != -1;
}


kern_return_t KittyMemory::getPageInfo(void *page_start, vm_region_submap_short_info_64 *outInfo) {
    vm_address_t region  = reinterpret_cast<vm_address_t>(page_start);
    vm_size_t region_len = 0;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    unsigned int depth = 0;
    return vm_region_recurse_64(mach_task_self(), &region, &region_len,
                                            &depth,
                                            (vm_region_recurse_info_t) outInfo,
                                            &info_count);
}


/*
refs to
- https://github.com/asLody/whale/blob/master/whale/src/platform/memory.cc
- CydiaSubstrate
*/
Memory_Status KittyMemory::memWrite(void *address, const void *buffer, size_t len) {
	if (address == NULL)
        return INV_ADDR;

    if (buffer == NULL)
        return INV_BUF;

    if (len < 1 || len > INT_MAX)
        return INV_LEN;
	
	// check for MSHookMemory that was added recently, but check for cydia existance first.
    if(cydiaExist() && findMSHookMemory(address, buffer, len)){ 
       return SUCCESS;
     }

    void * page_start  = reinterpret_cast<void *>(_PAGE_START_OF_(address));
    void * page_offset = reinterpret_cast<void *>(_PAGE_OFFSET_OF_(address));
    size_t page_len    = _PAGE_LEN_OF_(address, len);

    vm_region_submap_short_info_64 page_info;
    if(BAD_KERN_CALL(getPageInfo(page_start, &page_info)))
        return INV_KERN_CALL;

    if(page_info.protection & VM_PROT_WRITE){
        if(memcpy(address, buffer, len) != NULL){
           return SUCCESS;
        } else {
           return FAILED;
        }
    }

    void *new_map = mmap(NULL, page_len, _PROT_RW_, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if(new_map == NULL)
        return INV_MAP;

    task_t self_task = mach_task_self();


    if(BAD_KERN_CALL(vm_copy(self_task,
	                  reinterpret_cast<vm_address_t>(page_start), page_len, reinterpret_cast<vm_address_t>(new_map))))
        return INV_KERN_CALL;


    void *dst = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(new_map) + reinterpret_cast<uintptr_t>(page_offset));
    if(memcpy(dst, buffer, len) == NULL || !ProtectAddr(new_map, page_len, _PROT_RX_, true))
        return FAILED;

    vm_prot_t cur_protection, max_protection;
    mach_vm_address_t mach_vm_page_start = reinterpret_cast<mach_vm_address_t>(page_start);
    if(BAD_KERN_CALL(mach_vm_remap(self_task, &mach_vm_page_start, page_len, 0, VM_FLAGS_OVERWRITE,
                  self_task, reinterpret_cast<mach_vm_address_t>(new_map), TRUE, &cur_protection, &max_protection,
                  page_info.inheritance)))
        return INV_KERN_CALL;

    return SUCCESS;
}


Memory_Status KittyMemory::memRead(void *buffer, const void *addr, size_t len) {
    if (addr == NULL)
        return INV_ADDR;

    if (buffer == NULL)
        return INV_BUF;

    if (len < 1 || len > INT_MAX)
        return INV_LEN;

    if (memcpy(buffer, addr, len) != NULL)
        return SUCCESS;

    return FAILED;
}


std::string KittyMemory::read2HexStr(const void *addr, size_t len) {
    char temp[len];
    memset(temp, 0, len);

    const size_t bufferLen = len * 2 + 1;
    char buffer[bufferLen];
    memset(buffer, 0, bufferLen);

    std::string ret;

    if (memRead(temp, addr, len) != SUCCESS)
        return ret;

    for (int i = 0; i < len; i++) {
        sprintf(&buffer[i * 2], "%02X", (unsigned char) temp[i]);
    }

    ret += buffer;
    return ret;
}


KittyMemory::memory_file_info KittyMemory::getBaseInfo(){
    memory_file_info _info = {
        0,
        _dyld_get_image_header(0),
        _dyld_get_image_name(0),
        _dyld_get_image_vmaddr_slide(0)
    };
    return _info;
}



KittyMemory::memory_file_info KittyMemory::getMemoryFileInfo(const char *fileName){
    memory_file_info _info;

    int imageCount = _dyld_image_count();

    for(int i = 0; i < imageCount; i++) {
        const char *name = _dyld_get_image_name(i);
        const mach_header *header = _dyld_get_image_header(i);
        if(!strstr(name, fileName)) continue;

        memory_file_info new_info = {
            i, header, name, _dyld_get_image_vmaddr_slide(i)
        };

        _info = new_info;
    }
    return _info;
}


uint64_t KittyMemory::getAbsoluteAddress(const char *fileName, uint64_t address){
	memory_file_info info;
	if(fileName != NULL){
	   info = getMemoryFileInfo(fileName);
	} else {
	   info = getBaseInfo();
	}
    if(info.address == 0)
        return 0;
    return info.address + address;
}
