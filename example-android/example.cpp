#include <thread>
#include <string>
#include <cstdint>
#include <vector>

#include "../KittyMemory/KittyInclude.hpp"

// fancy struct for patches
struct MemPatches
{
    // let's assume we have patches for these functions for whatever game
    // boolean get_canShoot() function
    MemoryPatch get_canShoot;
    // int get_gold() function
    MemoryPatch get_gold;
    // etc...
} gPatches;

ProcMap g_il2cppBaseMap;

void test_thread()
{
    sleep(1);

    std::string processName = KittyMemory::getProcessName();
    KITTY_LOGI("Hello World: %s", processName.c_str());

    KITTY_LOGI("==================== SYMBOL LOOKUP ===================");

    // symbol lookup by name
    const char *lib_egl = KittyMemory::getMapsEndWith("/nb/libEGL.so").empty() ? "libEGL.so" : "/nb/libEGL.so";
    uintptr_t p_eglSwapBuffers = KittyScanner::findSymbol(lib_egl, "eglSwapBuffers");
    KITTY_LOGI("eglSwapBuffers = %p", (void *)p_eglSwapBuffers);

    // symbol lookup by name in all loaded shared objects
    auto v_eglSwapBuffers = KittyScanner::findSymbolAll("eglSwapBuffers");
    for (auto &it : v_eglSwapBuffers)
    {
        // first  = symbol address
        // second = library pathname
        KITTY_LOGI("Found %s at %p from %s", "eglSwapBuffers", (void *)it.first, it.second.c_str());
    }

    KITTY_LOGI("==================== GET ELF BASE ===================");

    // loop until our target library is found
    do
    {
        sleep(1);
        // getElfBaseMap can also find lib base even if it was loaded from zipped base.apk
        g_il2cppBaseMap = KittyMemory::getElfBaseMap("libil2cpp.so");
    } while (!g_il2cppBaseMap.isValid());
    KITTY_LOGI("il2cpp base: %p", (void *)(g_il2cppBaseMap.startAddress));

    // wait more to make sure lib is fully loaded and ready
    sleep(1);

    KITTY_LOGI("==================== MEMORY PATCH ===================");

    uintptr_t il2cppBase = g_il2cppBaseMap.startAddress;

    // with bytes, must specify bytes count
    gPatches.get_canShoot = MemoryPatch::createWithBytes(il2cppBase + 0x10948D4, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);
    
    // hex with or without spaces both are fine
    gPatches.get_canShoot = MemoryPatch::createWithHex(il2cppBase + 0x10948D4, "01 00 A0 E3 1E FF 2F E1");
    
    // (uses keystone assembler) insert ';' to seperate statements
    // its recommeneded to test your instructions on https://armconverter.com or https://shell-storm.org/online/Online-Assembler-and-Disassembler/
    // change MP_ASM_ARM64 to your targeted asm arch
    // MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86, MP_ASM_x86_64
    gPatches.get_canShoot = MemoryPatch::createWithAsm(il2cppBase + 0x10948D4, MP_ASM_ARM64, "mov x0, #1; ret");

    // format asm
    auto asm_fmt = KittyUtils::strfmt("mov x0, #%d; ret", 65536);
    gPatches.get_gold = MemoryPatch::createWithAsm(il2cppBase + 0x10948D4, MP_ASM_ARM64, asm_fmt);

    KITTY_LOGI("Patch Address: %p", (void *)gPatches.get_canShoot.get_TargetAddress());
    KITTY_LOGI("Patch Size: %zu", gPatches.get_canShoot.get_PatchSize());
    KITTY_LOGI("Current Bytes: %s", gPatches.get_canShoot.get_CurrBytes().c_str());

    // modify & print bytes
    if (gPatches.get_canShoot.Modify())
    {
        KITTY_LOGI("get_canShoot has been modified successfully");
        KITTY_LOGI("Current Bytes: %s", gPatches.get_canShoot.get_CurrBytes().c_str());
    }

    // restore & print bytes
    if (gPatches.get_canShoot.Restore())
    {
        KITTY_LOGI("get_canShoot has been restored successfully");
        KITTY_LOGI("Current Bytes: %s", gPatches.get_canShoot.get_CurrBytes().c_str());
    }

    KITTY_LOGI("=============== FIND NATIVE REGISTERS ===============");

    // get all maps of unity lib
    std::vector<ProcMap> unityMaps = KittyMemory::getMapsEndWith("libunity.so");

    // finding register native functions
    RegisterNativeFn nativeInjectEvent = KittyScanner::findRegisterNativeFn(unityMaps, "nativeInjectEvent");
    if (nativeInjectEvent.isValid())
        KITTY_LOGI("nativeInjectEvent = { %s, %s, %p }", nativeInjectEvent.name, nativeInjectEvent.signature, nativeInjectEvent.fnPtr);

    RegisterNativeFn nativeUnitySendMessage = KittyScanner::findRegisterNativeFn(unityMaps, "nativeUnitySendMessage");
    if (nativeUnitySendMessage.isValid())
        KITTY_LOGI("nativeUnitySendMessage = { %s, %s, %p }", nativeUnitySendMessage.name, nativeUnitySendMessage.signature, nativeUnitySendMessage.fnPtr);

    KITTY_LOGI("==================== PATTERN SCAN ===================");

    // scan within a memory range for bytes with mask x and ?

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    uintptr_t search_start = g_il2cppBaseMap.startAddress;
    uintptr_t search_end = g_il2cppBaseMap.endAddress;

    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes results: %zu", found_at_list.size());

    // scan with hex & get one result
    found_at = KittyScanner::findHexFirst(search_start, search_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex at: %p", (void *)found_at);
    // scan with hex & get all results
    found_at_list = KittyScanner::findHexAll(search_start, search_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex results: %zu", found_at_list.size());

    // scan with IDA pattern get one result
    found_at = KittyScanner::findIdaPatternFirst(search_start, search_end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found IDA pattern at: %p", (void *)found_at);
    // scan with IDA pattern get all results
    found_at_list = KittyScanner::findIdaPatternAll(search_start, search_end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found IDA pattern results: %zu", found_at_list.size());

    // scan with data type & get one result
    uint32_t data = 0xdeadbeef;
    found_at = KittyScanner::findDataFirst(search_start, search_end, &data, sizeof(data));
    KITTY_LOGI("found data at: %p", (void *)found_at);

    // scan with data type & get all results
    found_at_list = KittyScanner::findDataAll(search_start, search_end, &data, sizeof(data));
    KITTY_LOGI("found data results: %zu", found_at_list.size());

    KITTY_LOGI("====================== HEX DUMP =====================");

    // hex dump by default 8 rows with ASCII
    KITTY_LOGI("\n%s", KittyUtils::HexDump((void *)g_il2cppBaseMap.startAddress, 100).c_str());

    KITTY_LOGI("=====================================================");

    // 16 rows, no ASCII
    KITTY_LOGI("\n%s", KittyUtils::HexDump<16, false>((void *)g_il2cppBaseMap.startAddress, 100).c_str());
}

__attribute__((constructor)) void init()
{
    std::thread(test_thread).detach();
}