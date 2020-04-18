#import <pthread.h>
#import "KittyMemory/MemoryPatch.hpp"
#import "KittyMemory/writeData.hpp"


#define ARM64_RET_TRUE "\x20\x00\x80\xD2\xC0\x03\x5F\xD6"


static MemoryPatch minimapPatch;

void *HackThread(void *user_data) {

    // public bool get_CanShowOnMinimap(); // 0x1016BB4F4  ( outdated offset ofc )

      NSLog(@"============  New Patch Entry  =============");
      NSLog(@"============================================");
      NSLog(@"============================================");

    // pass NULL as fileName for base executable
    minimapPatch = MemoryPatch(NULL,
      /* relative address */ 0x1016BB4F4,
      /* patch bytes */ ARM64_RET_TRUE,
      /* patch bytes length */ 8);

    // also possible with hex
    // spaces in hex string are fine too
     minimapPatch = MemoryPatch::createWithHex(NULL, 0x1016BB4F4, "200080D2C0035FD6");
     minimapPatch.Modify();

    // log current bytes
    NSLog(@"get_CanShowOnMinimap Current Bytes: %s", minimapPatch.get_CurrBytes().c_str());

    if(minimapPatch.Modify()){ // modify and apply patch bytes
        NSLog(@"get_CanShowOnMinimap has been modified successfully");
	    NSLog(@"get_CanShowOnMinimap Current Bytes: %s", minimapPatch.get_CurrBytes().c_str());
    } else {
	    NSLog(@"Failed to patch get_CanShowOnMinimap");
    }


    // for restoring to original bytes
    if(minimapPatch.Restore()){ // restore and apply original bytes
       NSLog(@"get_CanShowOnMinimap has been restored successfully");
       NSLog(@"get_CanShowOnMinimap Current Bytes: %s", minimapPatch.get_CurrBytes().c_str());
    } else {
       NSLog(@"Failed to restore get_CanShowOnMinimap");
    }



	/* writedata alternative, check KittyMemory/writeData.hpp */

	// write 64 bit integer ( 8 bytes )
	if(writeData64(0x1016BB4F4, 0x200080D2C0035FD6)){
	    NSLog(@"get_CanShowOnMinimap has been modified successfully");
	}


	// or as 32 bit integer ( 4 bytes )
	if(writeData32(0x1016BB4F4, 0x200080D2) && writeData32(0x1016BB4F4 + 4, 0xC0035FD6)){
	    NSLog(@"get_CanShowOnMinimap has been modified successfully");
	}

	// and same thing for 1 and 2 bytes

    return NULL;
}

__attribute__((constructor))
static void runHacksInitializer(){
    pthread_t tid_hack;
    pthread_create(&tid_hack, NULL, HackThread, NULL);
}
