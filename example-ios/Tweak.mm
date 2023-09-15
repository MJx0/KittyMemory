#import <Foundation/Foundation.h>

#include <pthread.h>

#include <string>
#include <cstdint>
#include <vector>

#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>

#include "../KittyMemory/KittyInclude.hpp"


#define ARM64_RET_TRUE "\x20\x00\x80\xD2\xC0\x03\x5F\xD6"

// fancy struct for patches
 struct GlobalPatches {
     // let's assume we have patches for these functions for whatever game
	 // boolean function
     MemoryPatch canShowInMinimap;
     // etc...
 }gPatches;


void *test_thread(void *)
{
    // public bool get_CanShowOnMinimap(); // 0x1019C1F20  ( outdated offset ofc )

    NSLog(@"================  LOADED  ==================");

    sleep(5);

    NSLog(@"=============== MEMORY PATCH ===============");

    // pass NULL as fileName for base executable
    gPatches.canShowInMinimap = MemoryPatch::createWithBytes(nullptr,
                               /* relative address */ 0x1019C1F20,
                               /* patch bytes */ ARM64_RET_TRUE,
                               /* patch bytes length */ 8);

    gPatches.canShowInMinimap = MemoryPatch::createWithBytes(
                               /* absolute address */ 0x1019C1F20,
                               /* patch bytes */ ARM64_RET_TRUE,
                               /* patch bytes length */ 8);

    // lib name or framework
    gPatches.canShowInMinimap = MemoryPatch::createWithBytes("UnityFramework", 0x1019C1F20, ARM64_RET_TRUE, 8);
    
    // also possible with hex
    // spaces in hex string are fine too
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(nullptr, 0x1019C1F20, "200080D2C0035FD6");
    gPatches.canShowInMinimap = MemoryPatch::createWithHex("UnityFramework", 0x1019C1F20, "20 00 80 D2 C0 03 5F D6");

    // createWithAsm uses keystone assembler, insert ';' to seperate statements
    // it's recommeneded to test your instructions first on https://armconverter.com or https://shell-storm.org/online/Online-Assembler-and-Disassembler/
    // MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86, MP_ASM_x86_64
    gPatches.canShowInMinimap = MemoryPatch::createWithAsm(nullptr, 0x19C5D1C, MP_ASM_ARM64, "mov x0, #1; ret");
    
    // format asm string
    std::string asm_fmt = KittyUtils::strfmt("mov x0, #%d; ret", 65536);
    gPatches.canShowInMinimap = MemoryPatch::createWithAsm("UnityFramework", 0x19C5D1C, MP_ASM_ARM64, asm_fmt);

    // log current bytes
    NSLog(@"get_CanShowOnMinimap Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());

    // modify and apply patch bytes
    if (gPatches.canShowInMinimap.Modify())
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
        NSLog(@"get_CanShowOnMinimap Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }
    else
    {
        NSLog(@"Failed to patch get_CanShowOnMinimap");
    }

    /// restore and apply original bytes
    if (gPatches.canShowInMinimap.Restore())
    {
        NSLog(@"get_CanShowOnMinimap has been restored successfully");
        NSLog(@"get_CanShowOnMinimap Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }
    else
    {
        NSLog(@"Failed to restore get_CanShowOnMinimap");
    }


    // writedata alternative, check KittyMemory/writeData.hpp

    // write 64 bit integer ( 8 bytes )
    if (writeData64(nullptr, 0x1019C1F20, 0x200080D2C0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    // or as 32 bit integer ( 4 bytes )
    if (writeData32(nullptr, 0x1019C1F20, 0x200080D2) && writeData32(nullptr, 0x1019C1F20 + 4, 0xC0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    // for framework
    if (writeData64("Framework name", 0x1019C1F20, 0x200080D2C0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    NSLog(@"=============== PATTERN SCAN ===============");

    // scan within a memory range for bytes with mask x and ?

    const mach_header_64 *some_binary_header = (const mach_header_64 *)KittyMemory::getBaseInfo().header;

    // get start & end address of __TEXT segment
    unsigned long text_seg_size = 0;
    uintptr_t text_scan_start = (uintptr_t)getsegmentdata(some_binary_header, "__TEXT", &text_seg_size);
    uintptr_t text_scan_end = text_scan_start + text_seg_size;

    // get start & end address of __DATA segment
    unsigned long data_seg_size = 0;
    uintptr_t data_scan_start = (uintptr_t)getsegmentdata(some_binary_header, "__DATA", &data_seg_size);
    uintptr_t data_scan_end = data_scan_start + data_seg_size;

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(text_scan_start, text_scan_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    NSLog(@"found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(text_scan_start, text_scan_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    NSLog(@"found bytes results: %zu", found_at_list.size());

    // scan with hex & get one result
    found_at = KittyScanner::findHexFirst(text_scan_start, text_scan_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    NSLog(@"found hex at: %p", (void *)found_at);
    // scan with hex & get all results
    found_at_list = KittyScanner::findHexAll(text_scan_start, text_scan_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    NSLog(@"found hex results: %zu", found_at_list.size());

    // scan with data type & get one result
    uint32_t data = 0x99887766;
    found_at = KittyScanner::findDataFirst(data_scan_start, data_scan_end, &data, sizeof(data));
    NSLog(@"found data at: %p", (void *)found_at);

    // scan with data type & get all results
    found_at_list = KittyScanner::findDataAll(data_scan_start, data_scan_end, &data, sizeof(data));
    NSLog(@"found data results: %zu", found_at_list.size());


    NSLog(@"================= HEX DUMP =================");

    // hex dump by default 8 rows with ASCII
    NSLog(@"\n%s", KittyUtils::HexDump(some_binary_header, 100).c_str());

    NSLog(@"============================================");

    // 16 rows, no ASCII
    NSLog(@"\n%s", KittyUtils::HexDump<16, false>(some_binary_header, 100).c_str());

    return nullptr;
}

__attribute__((constructor))
void initializer()
{
    pthread_t ptid;
    pthread_create(&ptid, nullptr, test_thread, nullptr);
}
