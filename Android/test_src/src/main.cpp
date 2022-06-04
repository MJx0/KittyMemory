#include <pthread.h>
#include "Logger.h"

#include "KittyMemory/KittyMemory.h"
#include "KittyMemory/MemoryPatch.h"
#include "KittyMemory/KittyScanner.h"

using KittyMemory::ProcMap;

// fancy struct for patches
 struct GlobalPatches {
     // let's assume we have patches for these functions for whatever game
	 // like show in miniMap boolean function
     MemoryPatch canShowInMinimap;
     // etc...
 }gPatches;


// we will run our patches in a new thread so "sleep" doesn't block process main thread
void *my_test_thread(void *) {
	LOGD("I have been loaded...");
    
	// loop until our target library is found
	ProcMap il2cppMap;
	do {
		il2cppMap = KittyMemory::getLibraryMap("libil2cpp.so");
		sleep(1);
	} while(!il2cppMap.isValid());
	
    // wait more to make sure lib is fully loaded and ready
    sleep(1);
	

    // now we can do our stuff
    // let's say our patches are meant for an arm library

    // http://shell-storm.org/online/Online-Assembler-and-Disassembler/
    /*
    * mov r0, #1
    * bx lr
    */
	// address = 0x6A6144
    // bytes len = 8
    // patch simple boolean return
    gPatches.canShowInMinimap = MemoryPatch("libil2cpp.so", 0x6A6144,
                                          "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);

    // by default MemoryPatch will cache library map for faster lookup when use getAbsoluteAddress
    // You can disable this by passing false for last argument
    //gPatches.canShowInMinimap = MemoryPatch("libil2cpp.so", 0x6A6144, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8, false);

    // also possible with hex & no need to specify len
     gPatches.canShowInMinimap = MemoryPatch::createWithHex("libil2cpp.so", 0x6A6144, "0100A0E31EFF2FE1");

    // spaces are fine too
     gPatches.canShowInMinimap = MemoryPatch::createWithHex("libil2cpp.so", 0x6A6144, "01 00 A0 E3 1E FF 2F E1");

    LOGD("===== New Patch Entry =====");

    LOGD("Patch Address: %p", (void *)gPatches.canShowInMinimap.get_TargetAddress());
    LOGD("Patch Size: %zu", gPatches.canShowInMinimap.get_PatchSize());
    LOGD("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());

    // modify & print bytes
    if (gPatches.canShowInMinimap.Modify()) {
        LOGD("canShowInMinimap has been modified successfully");
        LOGD("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }
    
    // restore & print bytes
    if (gPatches.canShowInMinimap.Restore()) {
        LOGD("canShowInMinimap has been restored successfully");
        LOGD("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }

    // scan for bytes with mask x and ?
    uintptr_t found_at = KittyScanner::find_from_lib("libil2cpp.so", "\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxx??x?x");
    LOGD("scanner found bytes at: %p", (void*)found_at);

    LOGD("===========================");

    return NULL;
}

__attribute__((constructor))
void initializer() {
    pthread_t ptid;
    pthread_create(&ptid, NULL, my_test_thread, NULL);
}




