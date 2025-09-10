#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

#ifdef __ANDROID__
#include <dlfcn.h>
#include <unordered_map>
#include <mutex>
#endif

#include "KittyMemory.hpp"

namespace KittyScanner
{
    /**
     * Search for bytes within a memory range and return all results
     *
     * @start: search start address
     * @end: search end address
     * @bytes: bytes to search
     * @mask: bytes mask x/?
     *
     * @return vector list of all found bytes addresses
     */
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes,
                                        const std::string &mask);

    /**
     * Search for bytes within a memory range and return first result
     *
     * @start: search start address
     * @end: search end address
     * @bytes: bytes to search
     * @mask: bytes mask x/?
     *
     * @return first found bytes address
     */
    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask);

    /**
     * Search for hex within a memory range and return all results
     *
     * @start: search start address
     * @end: search end address
     * @hex: hex to search
     * @mask: hex mask x/?
     *
     * @return vector list of all found hex addresses
     */
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex,
                                      const std::string &mask);

    /**
     * Search for hex within a memory range and return first result
     *
     * @start: search start address
     * @end: search end address
     * @hex: hex to search
     * @mask: hex mask x/?
     *
     * @return first found hex address
     */
    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask);

    /**
     * Search for ida pattern within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return vector list of all found pattern addresses
     */
    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * Search for ida pattern within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return first found pattern address
     */
    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * Search for data within a memory range and return all results
     *
     * @start: search start address
     * @end: search end address
     * @data: data to search
     * @size: data size
     *
     * @return vector list of all found data addresses
     */
    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

    /**
     * Search for data within a memory range and return first result
     *
     * @start: search start address
     * @end: search end address
     * @data: data to search
     * @size: data size
     *
     * @return first found data address
     */
    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

#ifdef __ANDROID__

    class RegisterNativeFn
    {
    public:
        char *name;
        char *signature;
        void *fnPtr;

        RegisterNativeFn() : name(nullptr), signature(nullptr), fnPtr(nullptr)
        {
        }
        inline bool isValid() const
        {
            return (name != nullptr && signature != nullptr && fnPtr != nullptr);
        }
    };

#define KT_SOINFO_BUFFER_SZ (0x250)
    struct kitty_soinfo_t
    {
        uintptr_t ptr = 0;
        uintptr_t base = 0;
        size_t size = 0;
        uintptr_t phdr = 0;
        size_t phnum = 0;
        uintptr_t dyn = 0;
        uintptr_t strtab = 0;
        uintptr_t symtab = 0;
        size_t strsz = 0;
        uintptr_t bias = 0;
        uintptr_t next = 0;
        uint16_t e_machine = 0;
        std::string path;
        std::string realpath;
    };

    enum class EScanElfType : uint32_t
    {
        Any,
        Native,
        Emulated,
    };
    enum class EScanElfFilter : uint32_t
    {
        Any,
        System,
        App,
    };

    class ElfScanner
    {
    private:
        uintptr_t _elfBase;
        KT_ElfW(Ehdr) _ehdr;
        uintptr_t _phdr;
        std::vector<KT_ElfW(Phdr)> _phdrs;
        int _loads;
        uintptr_t _loadBias, _loadSize;
        uintptr_t _dynamic;
        std::vector<KT_ElfW(Dyn)> _dynamics;
        uintptr_t _stringTable, _symbolTable, _elfHashTable, _gnuHashTable;
        size_t _strsz, _syment;
        std::string _filepath;
        std::string _realpath;
        bool _fixedBySoInfo;
        bool _dsymbols_init;
        std::unordered_map<std::string, uintptr_t> _dsymbolsMap;
        std::vector<KittyMemory::ProcMap> _segments;
        std::vector<KittyMemory::ProcMap> _bssSegments;
        KittyMemory::ProcMap _baseSegment;

    public:
        ElfScanner()
            : _elfBase(0), _phdr(0), _loads(0), _loadBias(0), _loadSize(0), _dynamic(0), _stringTable(0),
              _symbolTable(0), _elfHashTable(0), _gnuHashTable(0), _strsz(0), _syment(0), _fixedBySoInfo(false),
              _dsymbols_init(false)
        {
        }

        ElfScanner(uintptr_t elfBase, const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps());
        ElfScanner(const kitty_soinfo_t &soinfo,
                   const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps());

        inline void refresh()
        {
            *this = ElfScanner(_elfBase);
        }

        inline bool isValid() const
        {
            return _elfBase && _loadSize && _phdr && _loadBias;
        }

        inline bool isFixedBySoInfo() const
        {
            return _fixedBySoInfo;
        }

        inline uintptr_t base() const
        {
            return _elfBase;
        }

        inline uintptr_t end() const
        {
            return _elfBase + _loadSize;
        }

        inline KT_ElfW(Ehdr) header() const
        {
            return _ehdr;
        }

        inline uintptr_t phdr() const
        {
            return _phdr;
        }

        inline std::vector<KT_ElfW(Phdr)> programHeaders() const
        {
            return _phdrs;
        }

        inline int loads() const
        {
            return _loads;
        }

        inline uintptr_t loadBias() const
        {
            return _loadBias;
        }

        inline uintptr_t loadSize() const
        {
            return _loadSize;
        }

        inline uintptr_t dynamic() const
        {
            return _dynamic;
        }

        inline std::vector<KT_ElfW(Dyn)> dynamics() const
        {
            return _dynamics;
        }

        inline uintptr_t stringTable() const
        {
            return _stringTable;
        }

        inline uintptr_t symbolTable() const
        {
            return _symbolTable;
        }

        inline size_t stringTableSize() const
        {
            return _strsz;
        }

        inline size_t symbolEntrySize() const
        {
            return _syment;
        }

        inline uintptr_t elfHashTable() const
        {
            return _elfHashTable;
        }

        inline uintptr_t gnuHashTable() const
        {
            return _gnuHashTable;
        }

        uintptr_t findSymbol(const std::string &symbolName) const;

        // debug symbols from SHT_SYMTAB on disk
        std::unordered_map<std::string, uintptr_t> dsymbols();
        uintptr_t findDebugSymbol(const std::string &symbolName);

        KittyMemory::ProcMap baseSegment() const
        {
            return _baseSegment;
        }

        std::vector<KittyMemory::ProcMap> segments() const
        {
            return _segments;
        }

        std::vector<KittyMemory::ProcMap> bssSegments() const
        {
            return _bssSegments;
        }

        inline std::string filePath() const
        {
            return _filepath;
        }

        inline std::string realPath() const
        {
            return _realpath;
        }

        inline bool isZipped() const
        {
            return _baseSegment.offset != 0;
        }

        inline bool isNative() const
        {
            int a = getProgramElf().header().e_machine, b = _ehdr.e_machine;
            return a != 0 && b != 0 && a == b;
        }

        inline bool isEmulated() const
        {
            int a = getProgramElf().header().e_machine, b = _ehdr.e_machine;
            return a != 0 && b != 0 && a != b;
        }

        /**
         * search for string "name" references to find the JNINativeMethod array
         */
        RegisterNativeFn findRegisterNativeFn(const std::string &name, const std::string &signature) const;

        // dump ELF to disk
        bool dumpToDisk(const std::string &destination) const;

        static ElfScanner &getProgramElf();

        /**
         * Fetch all in-memory loaded ELFs
         */
        static std::vector<ElfScanner> getAllELFs(EScanElfType type = EScanElfType::Any,
                                                  EScanElfFilter filter = EScanElfFilter::Any);

        /**
         * Find in-memory loaded ELF with name
         */
        static ElfScanner findElf(const std::string &path, EScanElfType type = EScanElfType::Any,
                                  EScanElfFilter filter = EScanElfFilter::Any);

        /**
         * lookup symbol name in all loaded ELFs
         * @return a vector of symbol absolute address and the ELF where the symbol was found in
         */
        static std::vector<std::pair<uintptr_t, ElfScanner>> findSymbolAll(const std::string &symbolName,
                                                                           EScanElfType type = EScanElfType::Any,
                                                                           EScanElfFilter filter = EScanElfFilter::Any);

        static ElfScanner createWithBase(uintptr_t elfBase,
                                         const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(elfBase, maps);
        }

        static ElfScanner createWithMap(const KittyMemory::ProcMap &elfMap,
                                         const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(elfMap.startAddress, maps);
        }

        static ElfScanner createWithSoInfo(const kitty_soinfo_t &soinfo,
                                           const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(soinfo, maps);
        }
    };

    class LinkerScanner : public ElfScanner
    {
    protected:
        struct
        {
            uintptr_t solist;
            uintptr_t somain;
            uintptr_t sonext;
        } _linker_syms;
        struct
        {
            uintptr_t base;
            uintptr_t size;
            uintptr_t phdr;
            uintptr_t phnum;
            uintptr_t dyn;
            uintptr_t strtab;
            uintptr_t symtab;
            uintptr_t strsz;
            uintptr_t bias;
            uintptr_t next;
        } _soinfo_offsets;
        bool _init;

        bool init();

    public:
        LinkerScanner() : ElfScanner(), _init(false)
        {
            memset(&_linker_syms, 0, sizeof(_linker_syms));
            memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        }

        LinkerScanner(uintptr_t linkerBase);
        LinkerScanner(const ElfScanner &linkerElf);

        inline static LinkerScanner &Get()
        {
            static LinkerScanner linker{};
            if (!linker.isValid() || !linker.init())
            {
                LinkerScanner tmp_linker{};
#ifdef __LP64__
                tmp_linker = LinkerScanner(
                    ElfScanner::findElf("/bin/linker64", EScanElfType::Native, EScanElfFilter::System));
#else
                tmp_linker = LinkerScanner(
                    ElfScanner::findElf("/bin/linker", EScanElfType::Native, EScanElfFilter::System));
#endif
                if (tmp_linker.isValid() && tmp_linker.init())
                    linker = tmp_linker;
            }
            return linker;
        }

        inline ElfScanner *asELF() const
        {
            return (ElfScanner *)this;
        }

        inline uintptr_t solist() const
        {
            if (!isValid() || !_linker_syms.solist)
                return 0;

            return *(uintptr_t *)(_linker_syms.solist);
        }

        inline uintptr_t somain() const
        {
            if (!isValid() || !_linker_syms.somain)
                return 0;

            return *(uintptr_t *)(_linker_syms.somain);
        }

        inline uintptr_t sonext() const
        {
            if (!isValid() || !_linker_syms.sonext)
                return 0;

            return *(uintptr_t *)(_linker_syms.sonext);
        }

        inline kitty_soinfo_t somainInfo() const
        {
            if (!isValid() || !_linker_syms.somain)
                return {};

            return infoFromSoInfo_(somain(), KittyMemory::getAllMaps());
        }

        inline kitty_soinfo_t sonextInfo() const
        {
            if (!isValid() || _linker_syms.sonext)
                return {};

            return infoFromSoInfo_(sonext(), KittyMemory::getAllMaps());
        }

        std::vector<kitty_soinfo_t> allSoInfo() const;

        kitty_soinfo_t findSoInfo(const std::string &name) const;

    private:
        kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const;
    };

    enum KT_JNICallType
    {
        KT_JNICallTypeRegular = 1,
        KT_JNICallTypeCriticalNative = 2,
    };

    struct nbItf_data_t
    {
        inline nbItf_data_t()
        {
            memset(this, 0, sizeof(nbItf_data_t));
        }

        int version;
#ifdef __LP64__
        uint32_t pad1;
#endif
        bool (*initialize)(const void *runtime_cbs, const char *private_dir, const char *instruction_set);
        void *(*loadLibrary)(const char *libpath, int flag);
        void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
        bool (*isSupported)(const char *libpath);
        const void *(*getAppEnv)(const char *instruction_set);
        bool (*isCompatibleWith)(uint32_t bridge_version);
        void *(*getSignalHandler)(int signal);
        int (*unloadLibrary)(void *handle);
        const char *(*getError)();
        bool (*isPathSupported)(const char *library_path);
        bool (*initAnonymousNamespace)(const char *public_ns_sonames, const char *anon_ns_library_path);
        void *(*createNamespace)(const char *name, const char *ld_library_path, const char *default_library_path,
                                 uint64_t type, const char *permitted_when_isolated_path, void *parent_ns);
        bool (*linkNamespaces)(void *from, void *to, const char *shared_libs_sonames);
        void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
        void *(*getVendorNamespace)();
        void *(*getExportedNamespace)(const char *name);
        void (*preZygoteFork)();
        void *(*getTrampolineWithJNICallType)(void *handle, const char *name, const char *shorty, uint32_t len,
                                              enum KT_JNICallType jni_call_type);
        void *(*getTrampolineForFunctionPointer)(const void *method, const char *shorty, uint32_t len,
                                                 enum KT_JNICallType jni_call_type);
        bool (*isNativeBridgeFunctionPointer)(const void *method);
    };

    class NativeBridgeScanner
    {
    private:
        ElfScanner _nbElf, _nbImplElf, _sodlElf;
        uintptr_t _sodl;
        struct
        {
            uintptr_t base;
            uintptr_t size;
            uintptr_t phdr;
            uintptr_t phnum;
            uintptr_t dyn;
            uintptr_t strtab;
            uintptr_t symtab;
            uintptr_t strsz;
            uintptr_t bias;
            uintptr_t next;
        } _soinfo_offsets;
        bool _init;
        bool _isHoudini;

        uintptr_t _nbItf;
        size_t _nbItf_data_size;
        nbItf_data_t _nbItf_data;

    public:
        bool (*fnNativeBridgeInitialized)();

        NativeBridgeScanner()
            : _sodl(0), _init(false), _isHoudini(false), _nbItf(0), _nbItf_data_size(0),
              fnNativeBridgeInitialized(nullptr)
        {
            memset(&_nbItf_data, 0, sizeof(_nbItf_data));
            memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        }

        inline static NativeBridgeScanner &Get()
        {
            static NativeBridgeScanner nb{};
            ((void)nb.init());
            return nb;
        }

        bool init();

        inline bool isValid() const
        {
            return _init;
        }

        inline uintptr_t sodl() const
        {
            return _sodl;
        }

        inline kitty_soinfo_t sodlInfo() const
        {
            if (!_init || !_sodl)
                return {};

            return infoFromSoInfo_(_sodl, KittyMemory::getAllMaps());
        }

        std::vector<kitty_soinfo_t> allSoInfo() const;

        kitty_soinfo_t findSoInfo(const std::string &name) const;

        inline size_t nbItfDataSize() const
        {
            return _nbItf_data_size;
        }

        inline nbItf_data_t nbItfData() const
        {
            return _nbItf_data;
        }

        inline bool isHoudini()
        {
            return _isHoudini;
        }

    private:
        kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const;
    };

    class NativeBridgeLinker
    {
    public:
        // native bride load library
        static void *dlopen(const std::string &path, int flags);
        // native bridge get trampoline
        static void *dlsym(void *handle, const std::string &sym_name);
        // native bridge dlerror
        static const char *dlerror();
        // native bridge dlladdr
        static bool dladdr(const void *addr, kitty_soinfo_t *info);
        // native bridge dl_iterate_phdr
        static void dl_iterate_phdr(const std::function<bool(const kitty_soinfo_t *info)> &callback);
    };

#endif // __ANDROID__

} // namespace KittyScanner
