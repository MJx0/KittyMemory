#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

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
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask);

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
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask);

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

        RegisterNativeFn() : name(nullptr), signature(nullptr), fnPtr(nullptr) {}
        inline bool isValid() const { return (name != nullptr && signature != nullptr && fnPtr != nullptr); }
    };

#define KT_SOINFO_BUFFER_SZ (0x200)
    struct soinfo_info_t
    {
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
        std::string path;
        std::string realpath;
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
        bool _headerless;
        bool _dsymbols_init;
        std::unordered_map<std::string, uintptr_t> _dsymbolsMap;

    public:
        ElfScanner()
            : _elfBase(0), _phdr(0), _loads(0), _loadBias(0), _loadSize(0), _dynamic(0), _stringTable(0), _symbolTable(0), _elfHashTable(0), _gnuHashTable(0), _strsz(0), _syment(0), _headerless(false), _dsymbols_init(false) {}

        ElfScanner(uintptr_t elfBase, const std::vector<KittyMemory::ProcMap> &maps);
        ElfScanner(uintptr_t elfBase) : ElfScanner(elfBase, KittyMemory::getAllMaps()) {}

        ElfScanner(const soinfo_info_t &soinfo, const std::vector<KittyMemory::ProcMap> &maps);
        ElfScanner(const soinfo_info_t &soinfo) : ElfScanner(soinfo, KittyMemory::getAllMaps()) {}

        static inline ElfScanner createWithBase(uintptr_t elfBase)
        {
            return ElfScanner(elfBase);
        }
        static inline ElfScanner createWithMap(const KittyMemory::ProcMap &map)
        {
            return ElfScanner(map.startAddress);
        }
        static inline ElfScanner createWithSoInfo(const soinfo_info_t &soinfo)
        {
            return ElfScanner(soinfo);
        }

        inline bool isValid() const
        {
            return _elfBase && _loadSize && _phdr && _loadBias;
        }

        inline bool isHeaderless() const { return _headerless; }

        inline uintptr_t base() const { return _elfBase; }

        inline uintptr_t end() const { return _elfBase + _loadSize; }

        inline KT_ElfW(Ehdr) header() const { return _ehdr; }

        inline uintptr_t phdr() const { return _phdr; }

        inline std::vector<KT_ElfW(Phdr)> programHeaders() const { return _phdrs; }

        inline int loads() const { return _loads; }

        inline uintptr_t loadBias() const { return _loadBias; }

        inline uintptr_t loadSize() const { return _loadSize; }

        inline uintptr_t dynamic() const { return _dynamic; }

        inline std::vector<KT_ElfW(Dyn)> dynamics() const { return _dynamics; }

        inline uintptr_t stringTable() const { return _stringTable; }

        inline uintptr_t symbolTable() const { return _symbolTable; }

        inline size_t stringTableSize() const { return _strsz; }

        inline size_t symbolEntrySize() const { return _syment; }

        inline uintptr_t elfHashTable() const { return _elfHashTable; }

        inline uintptr_t gnuHashTable() const { return _gnuHashTable; }

        uintptr_t findSymbol(const std::string &symbolName) const;

        // debug symbols from SHT_SYMTAB on disk
        std::unordered_map<std::string, uintptr_t> dsymbols();
        uintptr_t findDebugSymbol(const std::string &symbolName);

        KittyMemory::ProcMap baseSegment() const;

        std::vector<KittyMemory::ProcMap> segments() const;

        std::vector<KittyMemory::ProcMap> bssSegments() const;

        inline std::string filePath() const { return _filepath; }
        inline std::string realPath() const { return _realpath; }
        inline bool isZipped() const { return baseSegment().offset != 0; }

        /**
         * search for string "name" references to find the JNINativeMethod array
         */
        RegisterNativeFn findRegisterNativeFn(const std::string &name) const;

        // dump ELF to disk
        inline bool dumpToDisk(const std::string &destination)
        {
            return (isValid() && KittyMemory::dumpMemToDisk(_elfBase, _loadSize, destination));
        }

        static std::vector<ElfScanner> GetAllELFs();
        static std::vector<ElfScanner> GetAppELFs();
        static std::vector<ElfScanner> GetEmulatedELFs();
        
        static ElfScanner GetProgramElf();

        static ElfScanner findElf(const std::string &path);

        /**
         * lookup symbol name in all loaded ELFs
         * @return a vector of symbol absolute address and the ELF where the symbol was found in
         */
        static std::vector<std::pair<uintptr_t, ElfScanner>> findSymbolAll(const std::string &symbolName);
    };

    class LinkerScanner : public ElfScanner
    {
    private:
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

        inline static LinkerScanner Get()
        {
            static LinkerScanner linker{};
            if (!linker.isValid() || !linker.init())
            {
                LinkerScanner tmp_linker{};
#ifdef __LP64__
                tmp_linker = LinkerScanner(ElfScanner::findElf("/bin/linker64"));
#else
                tmp_linker = LinkerScanner(ElfScanner::findElf("/bin/linker"));
#endif
                if (tmp_linker.isValid() && tmp_linker.init())
                    linker = tmp_linker;
            }
            return linker;
        }

        inline ElfScanner *asELF() const { return (ElfScanner *)this; }

        inline uintptr_t solist() const
        {
            if (!isValid() || !_linker_syms.solist) return 0;

            return *(uintptr_t *)(_linker_syms.solist);
        }

        inline uintptr_t somain() const
        {
            if (!isValid() || !_linker_syms.somain) return 0;

            return *(uintptr_t *)(_linker_syms.somain);
        }

        inline uintptr_t sonext() const
        {
            if (!isValid() || !_linker_syms.sonext) return 0;

            return *(uintptr_t *)(_linker_syms.sonext);
        }

        inline soinfo_info_t GetSoMainInfo() const
        {
            if (!isValid() || !_linker_syms.somain) return {};

            return GetInfoFromSoInfo_(somain(), KittyMemory::getAllMaps());
        }

        inline soinfo_info_t GetSoNextInfo() const
        {
            if (!isValid() || _linker_syms.sonext) return {};

            return GetInfoFromSoInfo_(sonext(), KittyMemory::getAllMaps());
        }

        std::vector<soinfo_info_t> GetSoList() const;

    private:
        soinfo_info_t GetInfoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const;
    };
#endif  // __ANDROID__

}  // namespace KittyScanner