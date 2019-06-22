#include <pthread.h>
#include "KittyMemory/MemoryPatch.h"
#include "Logger.h"

// fancy struct for patches
 struct My_Patches {
     // let's assume we have patches for these functions for whatever game
	 // like show in miniMap boolean function
     MemoryPatch canShowInMinimap;
     // etc...
 }my_cool_Patches;


// we will run our patches in a new thread so "sleep" doesn't block process main thread
void *my_test_thread(void *) {
	LOGD("I have been loaded...");
    
	// loop until our target library is found
	ProcMap il2cppMap;
	do {
		il2cppMap = KittyMemory::getLibraryMap("libil2cpp.so");
		sleep(1);
	} while(!il2cppMap.isValid());
	
	

    // now here we do our stuff
    // let's say our patches are meant for an arm library

    // http://shell-storm.org/online/Online-Assembler-and-Disassembler/
    /*
    * mov r0, #1
    * bx lr
    */
	// address = 0x6A6144
    // bytes len = 8
    my_cool_Patches.canShowInMinimap = MemoryPatch("libil2cpp.so", 0x6A6144,
                                          "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);

    LOGD("===== New Patch Entry =====");
    LOGD("Patch Address: %p", (void *)my_cool_Patches.canShowInMinimap.get_TargetAddress());
    LOGD("Patch Size: %zu", my_cool_Patches.canShowInMinimap.get_PatchSize());
    LOGD("Current Bytes: %s", my_cool_Patches.canShowInMinimap.ToHexString().c_str());

    // modify & print bytes
    if (my_cool_Patches.canShowInMinimap.Modify()) {
        LOGD("canShowInMinimap has been modified successfully");
        LOGD("Current Bytes: %s", my_cool_Patches.canShowInMinimap.ToHexString().c_str());
    }
    // restore & print bytes
    if (my_cool_Patches.canShowInMinimap.Restore()) {
        LOGD("canShowInMinimap has been restored successfully");
        LOGD("Current Bytes: %s", my_cool_Patches.canShowInMinimap.ToHexString().c_str());
    }
    LOGD("===========================");

    return NULL;
}

__attribute__((constructor))
void initializer() {
    pthread_t ptid;
    pthread_create(&ptid, NULL, my_test_thread, NULL);
}




