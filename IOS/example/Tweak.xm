#import <Foundation/Foundation.h>

#import <pthread.h>

#import "../KittyMemory/KittyMemory.hpp"
#import "../KittyMemory/MemoryPatch.hpp"
#import "../KittyMemory/writeData.hpp"
#import "../KittyMemory/KittyScanner.hpp"
#import "../KittyMemory/KittyUtils.hpp"

using KittyMemory::MemoryFileInfo;

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
    gPatches.canShowInMinimap = MemoryPatch(NULL,
                               /* relative address */ 0x1019C1F20,
                               /* patch bytes */ ARM64_RET_TRUE,
                               /* patch bytes length */ 8);

    // also possible with hex
    // spaces in hex string are fine too
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(NULL, 0x1019C1F20, "200080D2C0035FD6");
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(NULL, 0x1019C1F20, "20 00 80 D2 C0 03 5F D6");

    // for framework
    //gPatches.canShowInMinimap = MemoryPatch::createWithHex("Framework name", 0x1019C1F20, "20 00 80 D2 C0 03 5F D6");

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
    if (writeData64(NULL, 0x1019C1F20, 0x200080D2C0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    // or as 32 bit integer ( 4 bytes )
    if (writeData32(NULL, 0x1019C1F20, 0x200080D2) && writeData32(NULL, 0x1019C1F20 + 4, 0xC0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    // for framework
    if (writeData64("Framework name", 0x1019C1F20, 0x200080D2C0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    if (writeData32("Framework name", 0x1019C1F20, 0x200080D2) && writeData32("Framework name", 0x1019C1F20 + 4, 0xC0035FD6))
    {
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
    }

    // and same thing for 1 and 2 bytes...

    NSLog(@"=============== PATTERN SCAN ===============");

    // scan for bytes with mask x and ?

    const mach_header *some_binary_header = KittyMemory::getMemoryFileInfo("main exe or framework").header;

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(some_binary_header, "__TEXT", "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    NSLog(@"found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(some_binary_header, "__TEXT", "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    NSLog(@"found bytes results: %zu", found_at_list.size());

    // scan with hex & get one result
    found_at = KittyScanner::findHexFirst(some_binary_header, "__TEXT", "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    NSLog(@"found hex at: %p", (void *)found_at);
    // scan with hex & get all results
    found_at_list = KittyScanner::findHexAll(some_binary_header, "__TEXT", "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    NSLog(@"found hex results: %zu", found_at_list.size());

    // scan with data type & get one result
    uint32_t data = 0x99887766;
    found_at = KittyScanner::findDataFirst(some_binary_header, "__DATA", &data, sizeof(data));
    NSLog(@"found data at: %p", (void *)found_at);

    // scan with data type & get all results
    found_at_list = KittyScanner::findDataAll(some_binary_header, "__DATA", &data, sizeof(data));
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
