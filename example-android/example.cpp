#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <link.h>

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

ElfScanner g_il2cppElf;

void test_thread()
{
    sleep(3);

    std::string processName = KittyMemory::getProcessName();
    KITTY_LOGI("Hello World: %s", processName.c_str());

    KITTY_LOGI("==================== GET ELF INFO ===================");

    // loop until our target library is found
    do
    {
        sleep(1);
        // findElf can find libs in split apk too
        g_il2cppElf = ElfScanner::findElf("libil2cpp.so");
        // use filter
        // g_il2cppElf = ElfScanner::findElf("libil2cpp.so", EScanElfType::Any, EScanElfFilter::App);

        // find via linker or native bridge solist
        auto nativeSo = LinkerScanner::Get().findSoInfo("libil2cpp.so");
        auto emulatedSo = NativeBridgeScanner::Get().findSoInfo("libil2cpp.so");

        if (nativeSo.ptr)
        {
            KITTY_LOGI("Found native libil2cpp.so soinfo at %p", (void *)nativeSo.ptr);
            g_il2cppElf = ElfScanner::createWithSoInfo(nativeSo);
        }
        if (emulatedSo.ptr)
        {
            KITTY_LOGI("Found emulated libil2cpp.so soinfo at %p", (void *)emulatedSo.ptr);
            g_il2cppElf = ElfScanner::createWithSoInfo(emulatedSo);
        }

        // incase il2cpp is renamed, you can find elf by any special symbol
        for (auto &it : ElfScanner::findSymbolAll("il2cpp_init", EScanElfType::Any, EScanElfFilter::App))
        {
            // make sure it has dynamic
            if (it.second.dynamic())
            {
                KITTY_LOGI("Found il2cpp_init at %p from %s", (void *)it.first, it.second.realPath().c_str());
                g_il2cppElf = it.second;
                break;
            }
        }
    } while (!g_il2cppElf.isValid());

    KITTY_LOGI("il2cpp filePath: %s", g_il2cppElf.filePath().c_str());
    KITTY_LOGI("il2cpp realPath: %s", g_il2cppElf.realPath().c_str());
    KITTY_LOGI("il2cpp base: %p", (void *)(g_il2cppElf.base()));
    KITTY_LOGI("il2cpp load_bias: %p", (void *)(g_il2cppElf.loadBias()));
    KITTY_LOGI("il2cpp load_size: %p", (void *)(g_il2cppElf.loadSize()));
    KITTY_LOGI("il2cpp end: %p", (void *)(g_il2cppElf.end()));
    KITTY_LOGI("il2cpp phdr: %p", (void *)(g_il2cppElf.phdr()));
    KITTY_LOGI("il2cpp phdrs count: %d", int(g_il2cppElf.programHeaders().size()));
    KITTY_LOGI("il2cpp dynamic: %p", (void *)(g_il2cppElf.dynamic()));
    KITTY_LOGI("il2cpp dynamics count: %d", int(g_il2cppElf.dynamics().size()));
    KITTY_LOGI("il2cpp strtab: %p", (void *)(g_il2cppElf.stringTable()));
    KITTY_LOGI("il2cpp symtab: %p", (void *)(g_il2cppElf.symbolTable()));
    KITTY_LOGI("il2cpp elfhash: %p", (void *)(g_il2cppElf.elfHashTable()));
    KITTY_LOGI("il2cpp gnuhash: %p", (void *)(g_il2cppElf.gnuHashTable()));
    KITTY_LOGI("il2cpp segments count: %d", int(g_il2cppElf.segments().size()));
    KITTY_LOGI("il2cpp inZip: %d", g_il2cppElf.isZipped() ? 1 : 0);
    KITTY_LOGI("il2cpp isNative: %d", g_il2cppElf.isNative() ? 1 : 0);
    KITTY_LOGI("il2cpp isEmulated: %d", g_il2cppElf.isEmulated() ? 1 : 0);

    // wait more to make sure lib is fully loaded and ready
    sleep(1);

    KITTY_LOGI("==================== SYMBOL LOOKUP ===================");

    KITTY_LOGI("il2cpp_init = %p", (void *)g_il2cppElf.findSymbol("il2cpp_init"));
    KITTY_LOGI("il2cpp_string_new = %p", (void *)g_il2cppElf.findSymbol("il2cpp_string_new"));

    // symbol lookup by name in all loaded elfs
    // auto v_eglSwapBuffers = ElfScanner::findSymbolAll("eglSwapBuffers");
    // use filters
    auto v_eglSwapBuffers = ElfScanner::findSymbolAll("eglSwapBuffers", EScanElfType::Any, EScanElfFilter::System);
    // scan natives only
    // auto v_eglSwapBuffers = ElfScanner::findSymbolAll("eglSwapBuffers", EScanElfType::Native,
    // EScanElfFilter::System); scan emulated only auto v_eglSwapBuffers = ElfScanner::findSymbolAll("eglSwapBuffers",
    // EScanElfType::Emulated, EScanElfFilter::System);

    for (auto &it : v_eglSwapBuffers)
    {
        // first  = symbol address
        // second = ELF object where symbol was found
        KITTY_LOGI("Found eglSwapBuffers at %p from %s", (void *)it.first, it.second.realPath().c_str());
    }

    KITTY_LOGI("=============== FIND NATIVE REGISTERS ===============");

    // get loaded unity ELF
    auto unityELF = ElfScanner::findElf("libunity.so");

    // finding register native functions
    RegisterNativeFn nativeInjectEvent = unityELF.findRegisterNativeFn("nativeInjectEvent",
                                                                       "(Landroid/view/InputEvent;)Z");
    // new nativeInjectEvent has second integer param
    if (!nativeInjectEvent.isValid())
        nativeInjectEvent = unityELF.findRegisterNativeFn("nativeInjectEvent", "(Landroid/view/InputEvent;I)Z");

    if (nativeInjectEvent.isValid())
        KITTY_LOGI("nativeInjectEvent = { %s, %s, %p }", nativeInjectEvent.name, nativeInjectEvent.signature,
                   nativeInjectEvent.fnPtr);
    else
        KITTY_LOGI("nativeInjectEvent = NULL");

    RegisterNativeFn nativeUnitySendMessage = unityELF.findRegisterNativeFn(
        "nativeUnitySendMessage", "(Ljava/lang/String;Ljava/lang/String;[B)V");
    if (nativeUnitySendMessage.isValid())
        KITTY_LOGI("nativeUnitySendMessage = { %s, %s, %p }", nativeUnitySendMessage.name,
                   nativeUnitySendMessage.signature, nativeUnitySendMessage.fnPtr);
    else
        KITTY_LOGI("nativeUnitySendMessage = NULL");

    KITTY_LOGI("==================== MEMORY PATCH ===================");

    uintptr_t il2cppBase = g_il2cppElf.base();

    // with bytes, must specify bytes count
    gPatches.get_canShoot = MemoryPatch::createWithBytes(il2cppBase + 0x1D8B054, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);

    // hex with or without spaces both are fine
    gPatches.get_canShoot = MemoryPatch::createWithHex(il2cppBase + 0x1D8B054, "01 00 A0 E3 1E FF 2F E1");

#ifndef kNO_KEYSTONE
    // (uses keystone assembler) insert ';' to seperate statements
    // its recommeneded to test your instructions on https://armconverter.com or
    // https://shell-storm.org/online/Online-Assembler-and-Disassembler/ change
    // MP_ASM_ARM64 to your targeted asm arch MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86,
    // MP_ASM_x86_64
    gPatches.get_canShoot = MemoryPatch::createWithAsm(il2cppBase + 0x1D8B054, MP_ASM_ARM64, "mov x0, #1; ret");

    // format asm
    auto asm_fmt = KittyUtils::String::Fmt("mov x0, #%d; ret", 65536);
    gPatches.get_gold = MemoryPatch::createWithAsm(il2cppBase + 0x1D8B054, MP_ASM_ARM64, asm_fmt);
#endif

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

    KITTY_LOGI("==================== PATTERN SCAN ===================");

    // scan within a memory range for bytes with mask x and ?

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    uintptr_t search_start = g_il2cppElf.baseSegment().startAddress;
    uintptr_t search_end = g_il2cppElf.baseSegment().endAddress;

    // scan with direct bytes & get one result
    found_at = KittyScanner::findBytesFirst(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99",
                                            "xxxx??x?x");
    KITTY_LOGI("found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = KittyScanner::findBytesAll(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99",
                                               "xxxx??x?x");
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
    KITTY_LOGI("\n%s", KittyUtils::HexDump((void *)g_il2cppElf.baseSegment().startAddress, 100).c_str());

    KITTY_LOGI("=====================================================");

    // 16 rows, no ASCII
    KITTY_LOGI("\n%s", KittyUtils::HexDump<16, false>((void *)g_il2cppElf.baseSegment().startAddress, 100).c_str());

    KITTY_LOGI("===================== ELFS SCAN ====================");

    // gret all elfs
    const auto elfs = ElfScanner::getAllELFs();
    // get app related elfs
    // const auto elfs = ElfScanner::getAllELFs(EScanElfType::Any, EScanElfFilter::App);
    // get emulated system elfs on emulator
    // const auto elfs = ElfScanner::getAllELFs(EScanElfType::Emulated, EScanElfFilter::System);

    for (const auto &it : elfs)
    {
        KITTY_LOGI("elfs(%p) -> %s", (void *)it.base(), it.realPath().c_str());
    }

#if defined(__x86_64__) || defined(__i386__)
    KITTY_LOGI("============== NativeBridge Linker ==============");

    void *libcHandle = NativeBridgeLinker::dlopen("path/to/lib", RTLD_NOW);
    if (libcHandle)
    {
        void *fnInit = NativeBridgeLinker::dlsym(libcHandle, "my_init_func");
        KITTY_LOGI("nb] handle(%p) - fnInit(%p)", libcHandle, fnInit);
        if (fnInit)
        {
            // call
            ((void (*)(void *))fnInit)(nullptr);
        }
    }
    else
    {
        const char *err = NativeBridgeLinker::dlerror();
        if (err)
            KITTY_LOGE("dlerror %s", err);
    }

    NativeBridgeLinker::dl_iterate_phdr([](const kitty_soinfo_t *info) -> bool {
        KITTY_LOGI("nb] %p -> %s", (void *)info->base, info->realpath.c_str() ? info->realpath.c_str() : "");
        return false;
    });

    kitty_soinfo_t info{};
    if (NativeBridgeLinker::dladdr((void *)il2cppBase, &info))
    {
        KITTY_LOGI("nb dladdr] %p -> %s", (void *)info.base, info.realpath.c_str());
    }
#endif
}

__attribute__((constructor)) void init()
{
    std::thread(test_thread).detach();
}

/*#include <jni.h>

extern "C" jint JNIEXPORT JNI_OnLoad(JavaVM *vm, void *key)
{
    KITTY_LOGI("========================");
    KITTY_LOGI("JNI_OnLoad(%p, %p)", vm, key);

    // check if called by injector
    if (key != (void *)1337)
        return JNI_VERSION_1_6;

    KITTY_LOGI("JNI_OnLoad called by injector.");

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_OK)
    {
        KITTY_LOGI("JavaEnv: %p.", env);
        // ...
    }

    std::thread(test_thread).detach();

    return JNI_VERSION_1_6;
}*/
