#include <pthread.h>

#include <vector>

#include <KittyMemory/KittyMemory.h>
#include <KittyMemory/MemoryPatch.h>
#include <KittyMemory/KittyScanner.h>
#include <KittyMemory/KittyUtils.h>

using KittyMemory::ProcMap;
using KittyScanner::RegisterNativeFn;

// define kITTYMEMORY_DEBUG in cpp flags for KITTY_LOGI & KITTY_LOGE outputs


// fancy struct for patches
 struct GlobalPatches {
     // let's assume we have patches for these functions for whatever game
	 // boolean function
     MemoryPatch canShowInMinimap;
     // etc...
 }gPatches;


ProcMap g_il2cppBaseMap;

void *test_thread(void *) {
    KITTY_LOGI("======================= LOADED ======================");

    // loop until our target library is found
    
    do {
        sleep(1);
        g_il2cppBaseMap = KittyMemory::getLibraryBaseMap("libil2cpp.so");
    } while (!g_il2cppBaseMap.isValid());

    KITTY_LOGI("il2cpp base: %p", (void*)(g_il2cppBaseMap.startAddress));

    // wait more to make sure lib is fully loaded and ready
    sleep(1);
    
    KITTY_LOGI("==================== MEMORY PATCH ===================");
        
    /* patch with direct bytes */
    gPatches.canShowInMinimap = MemoryPatch(g_il2cppBaseMap, 0x6A6144, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);
    // absolute address
    gPatches.canShowInMinimap = MemoryPatch(g_il2cppBaseMap.startAddress + 0x6A6144, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);

    // also possible with hex & no need to specify len
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(g_il2cppBaseMap, 0x6A6144, "0100A0E31EFF2FE1");

    // spaces are fine too
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(g_il2cppBaseMap, 0x6A6144, "01 00 A0 E3 1E FF 2F E1");

    // absolute address
    gPatches.canShowInMinimap = MemoryPatch::createWithHex(g_il2cppBaseMap.startAddress + 0x6A6144, "01 00 A0 E3 1E FF 2F E1");

    KITTY_LOGI("Patch Address: %p", (void *)gPatches.canShowInMinimap.get_TargetAddress());
    KITTY_LOGI("Patch Size: %zu", gPatches.canShowInMinimap.get_PatchSize());
    KITTY_LOGI("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());

    // modify & print bytes
    if (gPatches.canShowInMinimap.Modify()) {
        KITTY_LOGI("canShowInMinimap has been modified successfully");
        KITTY_LOGI("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }
    
    // restore & print bytes
    if (gPatches.canShowInMinimap.Restore()) {
        KITTY_LOGI("canShowInMinimap has been restored successfully");
        KITTY_LOGI("Current Bytes: %s", gPatches.canShowInMinimap.get_CurrBytes().c_str());
    }

    
    KITTY_LOGI("=============== FIND NATIVE REGISTERS ===============");

    // get all maps of unity lib
    std::vector<ProcMap> unityMaps = KittyMemory::getMapsByName("libunity.so");
    
    // finding register native functions
    RegisterNativeFn nativeInjectEvent = KittyScanner::findRegisterNativeFn(unityMaps, "nativeInjectEvent");
    if(nativeInjectEvent.isValid()) {
        KITTY_LOGI("nativeInjectEvent = { %s, %s, %p }", nativeInjectEvent.name, nativeInjectEvent.signature, nativeInjectEvent.fnPtr);
    }

    RegisterNativeFn nativeUnitySendMessage = KittyScanner::findRegisterNativeFn(unityMaps, "nativeUnitySendMessage");
    if(nativeUnitySendMessage.isValid()) {
        KITTY_LOGI("nativeUnitySendMessage = { %s, %s, %p }", nativeUnitySendMessage.name, nativeUnitySendMessage.signature, nativeUnitySendMessage.fnPtr);
    }

    RegisterNativeFn nativeRender = KittyScanner::findRegisterNativeFn(unityMaps, "nativeRender");
    if(nativeRender.isValid()) {
        KITTY_LOGI("nativeInjectEvent = { %s, %s, %p }", nativeRender.name, nativeRender.signature, nativeRender.fnPtr);
    }


    KITTY_LOGI("==================== PATTERN SCAN ===================");

    // scan for bytes with mask x and ?

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    
    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(g_il2cppBaseMap, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes at: %p", (void*)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(g_il2cppBaseMap, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes results: %zu", found_at_list.size());


    // scan with hex & get one result
    found_at = KittyScanner::findHexFirst(g_il2cppBaseMap, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex at: %p", (void*)found_at);
    // scan with hex & get all results
    found_at_list = KittyScanner::findHexAll(g_il2cppBaseMap, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex results: %zu", found_at_list.size());


    // scan with data type & get one result
    uint32_t data = 0x99887766;
    found_at = KittyScanner::findDataFirst(g_il2cppBaseMap, &data, sizeof(data));
    KITTY_LOGI("found data at: %p", (void*)found_at);

    // scan with data type & get all results
    found_at_list = KittyScanner::findDataAll(g_il2cppBaseMap, &data, sizeof(data));
    KITTY_LOGI("found data results: %zu", found_at_list.size());


    KITTY_LOGI("====================== HEX DUMP =====================");

    // hex dump by default 8 rows with ASCII
    KITTY_LOGI("%s", KittyUtils::HexDump((void*)g_il2cppBaseMap.startAddress, 100).c_str());

    KITTY_LOGI("=====================================================");
    
    // 16 rows, no ASCII
    KITTY_LOGI("%s", KittyUtils::HexDump<16, false>((void*)g_il2cppBaseMap.startAddress, 100).c_str());

    return nullptr;
}

__attribute__((constructor))
void initializer()
{
    pthread_t ptid;
    pthread_create(&ptid, nullptr, test_thread, nullptr);
}