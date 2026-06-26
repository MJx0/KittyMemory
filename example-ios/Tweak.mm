#include <thread>
#include <string>
#include <cstdint>
#include <vector>

#import <Foundation/Foundation.h>


// include KittyMemory
#include "../KittyMemory/KittyInclude.hpp"

// fancy struct for patches
struct MemPatches
{
    // let's assume we have patches for these functions for whatever game
    // boolean function
    MemoryPatch get_canShoot;
    // int function
    MemoryPatch get_gold;
    // etc...
} gPatches;

MachOImage g_MachoImg;

void test_thread()
{
    KITTY_LOGI("================== THREAD LOADED =====================");

    KITTY_LOGI("App Executable: %{public}s", MachOImage::getMainImage().name());

    // loop until our target binary is found
    do
    {
        sleep(1);

        // base executable
        g_MachoImg = MachOImage::getMainImage();

        // or framework
        // g_MachoImg = MachOImage::findMachOImage("UnityFramework");

    } while (!g_MachoImg.isValid());

    KITTY_LOGI("UnityFramework slide: %p", (void *)g_MachoImg.slide());
    KITTY_LOGI("UnityFramework start: %p", (void *)g_MachoImg.start());
    KITTY_LOGI("UnityFramework end: %p", (void *)g_MachoImg.end());
    KITTY_LOGI("UnityFramework size: %p", (void *)g_MachoImg.size());

    KITTY_LOGI("=========== SEGMENTS & SECTIONS ============");

    KITTY_LOGI("segments count: %d", int(g_MachoImg.segments().size()));
    for (auto &it : g_MachoImg.segments())
    {
        KITTY_LOGI("%{public}s -> %p", it.first.c_str(), (void *)it.second.start);
    }

    KITTY_LOGI("sections count: %d", int(g_MachoImg.sections().size()));
    for (auto &it : g_MachoImg.sections())
    {
        KITTY_LOGI("%{public}s -> %p", it.first.c_str(), (void *)it.second.start);
    }

    KITTY_LOGI("=============== FIND SYMBOL ================");

    KITTY_LOGI("symbols count: %d", int(g_MachoImg.symbols().size()));

    // you may have to prefix function name with underscore

    // with existing MachOImage object
    KITTY_LOGI("il2cpp_string_new: %p", (void *)(g_MachoImg.findSymbol("_il2cpp_string_new")));

    KITTY_LOGI("==================== MEMORY PATCH ===================");

    uintptr_t unityBase = g_MachoImg.slide();

#ifndef kNO_KEYSTONE
    // with asm (uses keystone assembler) insert ';' to seperate statements
    // its recommeneded to test your instructions on https://armconverter.com or
    // https://shell-storm.org/online/Online-Assembler-and-Disassembler/ change MP_ASM_ARM64 to your targeted asm arch
    // MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86, MP_ASM_x86_64
    gPatches.get_canShoot = MemoryPatch::createWithAsm(unityBase + 0x10948D4, MP_ASM_ARM64, "mov x0, #1; ret");

    // format asm
    std::string asm_fmt = KittyUtils::String::fmt("mov x0, #%d; ret", 65536);
    gPatches.get_gold = MemoryPatch::createWithAsm(unityBase + 0xE4EB8, MP_ASM_ARM64, asm_fmt);
#endif


    // hex with or without spaces both are fine
    gPatches.get_canShoot = MemoryPatch::createWithHex(unityBase + 0x10948D4, "01 00 A0 E3 1E FF 2F E1");


    // raw bytes
    gPatches.get_canShoot = MemoryPatch::createWithBytes(unityBase + 0x1019C1F20,
                                                         "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1",
                                                         8);


    KITTY_LOGI("Patch Address: %p", (void *)gPatches.get_canShoot.get_TargetAddress());
    KITTY_LOGI("Patch Size: %zu", gPatches.get_canShoot.get_PatchSize());
    KITTY_LOGI("Current Bytes: %{public}s", gPatches.get_canShoot.get_CurrBytes().c_str());

    // modify & print bytes
    if (gPatches.get_canShoot.Modify())
    {
        KITTY_LOGI("get_canShoot has been modified successfully");
        KITTY_LOGI("Current Bytes: %{public}s", gPatches.get_canShoot.get_CurrBytes().c_str());
    }

    // restore & print bytes
    if (gPatches.get_canShoot.Restore())
    {
        KITTY_LOGI("get_canShoot has been restored successfully");
        KITTY_LOGI("Current Bytes: %{public}s", gPatches.get_canShoot.get_CurrBytes().c_str());
    }

    // writedata alternative, check KittyMemory/writeData.hpp

    // write 64 bit integer ( 8 bytes )
    if (writeData64(unityBase + 0x1019C1F20, 0x200080D2C0035FD6))
        KITTY_LOGI("get_canShoot has been modified successfully");

    // or as 32 bit integer ( 4 bytes )
    if (writeData32(unityBase + 0x1019C1F20, 0x200080D2) && writeData32(unityBase + 0x1019C1F20 + 4, 0xC0035FD6))
        KITTY_LOGI("get_canShoot has been modified successfully");


    KITTY_LOGI("=============== PATTERN SCAN ===============");

    // scan within a memory range for bytes with mask x and ?

    // get start & end address of __TEXT segment
    mem_range_info_t text_seg = g_MachoImg.findSegment("__TEXT");
    KITTY_LOGI("__TEXT Address: %p | Size: %p", (void *)text_seg.start, (void *)text_seg.size);

    // get start & end address of __DATA segment
    mem_range_info_t data_seg = g_MachoImg.findSegment("__DATA");
    KITTY_LOGI("__DATA Address: %p | Size: %p", (void *)data_seg.start, (void *)data_seg.size);

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(text_seg.start,
                                            text_seg.end,
                                            "\x33\x44\x55\x66\x00\x77\x88\x00\x99",
                                            "xxxx??x?x");
    KITTY_LOGI("found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(text_seg.start,
                                               text_seg.end,
                                               "\x33\x44\x55\x66\x00\x77\x88\x00\x99",
                                               "xxxx??x?x");
    KITTY_LOGI("found bytes results: %zu", found_at_list.size());

    // scan with hex & get one result
    found_at = KittyScanner::findHexFirst(text_seg.start, text_seg.end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex at: %p", (void *)found_at);
    // scan with hex & get all results
    found_at_list = KittyScanner::findHexAll(text_seg.start, text_seg.end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex results: %zu", found_at_list.size());

    // scan with IDA pattern get one result
    found_at = KittyScanner::findIdaPatternFirst(text_seg.start, text_seg.end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found IDA pattern at: %p", (void *)found_at);
    // scan with IDA pattern get all results
    found_at_list = KittyScanner::findIdaPatternAll(text_seg.start, text_seg.end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found IDA pattern results: %zu", found_at_list.size());

    // scan with data type & get one result
    uint32_t data = 0x99887766;
    found_at = KittyScanner::findDataFirst(data_seg.start, data_seg.end, &data, sizeof(data));
    KITTY_LOGI("found data at: %p", (void *)found_at);

    // scan with data type & get all results
    found_at_list = KittyScanner::findDataAll(data_seg.start, data_seg.end, &data, sizeof(data));
    KITTY_LOGI("found data results: %zu", found_at_list.size());

    KITTY_LOGI("================= HEX DUMP =================");

    // hex dump by default 8 rows with ASCII
    KITTY_LOGI("%{public}s", KittyUtils::Data::hexDump(g_MachoImg.header(), sizeof(*g_MachoImg.header())).c_str());

    KITTY_LOGI("============================================");

    // 16 rows, no ASCII
    KITTY_LOGI("\n%{public}s",
               KittyUtils::Data::hexDump<16, false>(g_MachoImg.header(), sizeof(*g_MachoImg.header())).c_str());
}

__attribute__((constructor)) void init()
{
    KITTY_LOGI("====================== LOADED =====================");
    std::thread(test_thread).detach();
}