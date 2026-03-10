#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

#ifdef __ANDROID__
#include <link.h>
#include <dlfcn.h>
#include <unordered_map>
#include <mutex>
#endif

#include "KittyMemory.hpp"

namespace KittyScanner
{
    /**
     * @brief Searches for bytes within a memory range and returns all results.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param bytes: The bytes to search for.
     * @param mask: The bytes mask using 'x' and '?' wildcards.
     *
     * @return A vector containing all addresses where the bytes were found.
     */
    std::vector<uintptr_t> findBytesAll(const uintptr_t start,
                                        const uintptr_t end,
                                        const char *bytes,
                                        const std::string &mask);

    /**
     * @brief Searches for bytes within a memory range and returns the first result.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param bytes: The bytes to search for.
     * @param mask: The bytes mask using 'x' and '?' wildcards.
     *
     * @return The first address where the bytes were found, or `0` if not found.
     */
    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask);

    /**
     * @brief Searches for hex within a memory range and returns all results.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param hex: The hex bytes to search for.
     * @param mask: The hex mask using 'x' and '?' wildcards.
     *
     * @return A vector containing all addresses where the hex was found.
     */
    std::vector<uintptr_t> findHexAll(const uintptr_t start,
                                      const uintptr_t end,
                                      std::string hex,
                                      const std::string &mask);

    /**
     * @brief Searches for hex within a memory range and returns the first result.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param hex: The hex bytes to search for.
     * @param mask: The hex mask using 'x' and '?' wildcards.
     *
     * @return The first address where the hex was found, or `0` if not found.
     */
    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask);

    /**
     * @brief Searches for a pattern within a memory range using the IDA pattern syntax and returns all results.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param pattern: The IDA pattern string (e.g., "FF DD ? 99 CC ? 00").
     *
     * @return A vector containing all addresses where the pattern was found.
     */
    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * @brief Searches for a pattern within a memory range using the IDA pattern syntax and returns the first result.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param pattern: The IDA pattern string (e.g., "FF DD ? 99 CC ? 00").
     *
     * @return The first address where the pattern was found, or `0` if not found.
     */
    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * @brief Searches for data within a memory range and returns all results.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param data: A pointer to the data to search for.
     * @param size: The size of the data to search for.
     *
     * @return A vector containing all addresses where the data was found.
     */
    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

    /**
     * @brief Searches for data within a memory range and returns the first result.
     *
     * @param start: The starting address to search.
     * @param end: The ending address to search.
     * @param data: A pointer to the data to search for.
     * @param size: The size of the data to search for.
     *
     * @return The first address where the data was found, or `0` if not found.
     */
    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size);

#ifdef __ANDROID__
    /**
     * @brief Structure to hold info of a registered native JNI function
     */
    struct RegisterNativeFn
    {
    public:
        char *name;
        char *signature;
        void *fnPtr;

        RegisterNativeFn() : name(nullptr), signature(nullptr), fnPtr(nullptr)
        {
        }

        /**
         * @brief Check if JNI function is valid.
         */
        inline bool isValid() const
        {
            return (name != nullptr && signature != nullptr && fnPtr != nullptr);
        }
    };

#define KT_SOINFO_BUFFER_SZ (0x250)

    /**
     * @brief Structure to hold info of linker soinfo
     */
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

    /**
     * @brief Enum class representing the type of ELF file to scan for.
     */
    enum class EScanElfType : uint32_t
    {
        Any,
        Native,
        Emulated,
    };

    /**
     * @brief Enum class representing the filter criteria for ELF files to scan.
     */
    enum class EScanElfFilter : uint32_t
    {
        Any,
        System,
        App,
    };

    /**
     * @brief Represents a scanner for memory ELF files.
     * This class is used to scan ELF files from memory and extract information about their contents.
     */
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

        /**
         * @brief Constructor for ElfScanner class.
         * This constructor initializes the ElfScanner class with the given ELF base address.
         *
         * @param elfBase The base address of the ELF file.
         * @param maps The vector of cached process memory maps (optional).
         */
        ElfScanner(uintptr_t elfBase, const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps());

        /**
         * @brief Constructor for ElfScanner class.
         * This constructor initializes the ElfScanner class with the given soinfo.
         *
         * @param soinfo The soinfo of the ELF file.
         * @param maps The vector of cached process memory maps (optional).
         */
        ElfScanner(const kitty_soinfo_t &soinfo,
                   const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps());

        /**
         * @brief Refreshes the ElfScanner class with the current ELF base.
         */
        inline void refresh()
        {
            *this = ElfScanner(_elfBase);
        }

        /**
         * @brief Checks if the ElfScanner class is valid.
         */
        inline bool isValid() const
        {
            return _elfBase && _loadSize && _phdr && _loadBias;
        }

        /**
         * @brief Checks if the ELF file is fixed by soinfo.
         * Some Elf headers are obfuscated or removed,
         * \ref createWithSoInfo(const kitty_soinfo_t&, const std::vector<KittyMemory::ProcMap>&) may fix header.
         */
        inline bool isFixedBySoInfo() const
        {
            return _fixedBySoInfo;
        }

        /**
         * @brief Elf's Base address in memory.
         */
        inline uintptr_t base() const
        {
            return _elfBase;
        }

        /**
         * @brief Elf's end address in memory.
         */
        inline uintptr_t end() const
        {
            return _elfBase + _loadSize;
        }

        /**
         * @brief Elf's header.
         */
        inline KT_ElfW(Ehdr) header() const
        {
            return _ehdr;
        }

        /**
         * @brief Elf's program header address in memory.
         */
        inline uintptr_t phdr() const
        {
            return _phdr;
        }

        /**
         * @brief Vector of Elf's program headers.
         */
        inline std::vector<KT_ElfW(Phdr)> programHeaders() const
        {
            return _phdrs;
        }

        /**
         * @brief Elf's number of loads.
         */
        inline int loads() const
        {
            return _loads;
        }

        /**
         * @brief Elf's load bias address in memory.
         */
        inline uintptr_t loadBias() const
        {
            return _loadBias;
        }

        /**
         * @brief Elf's load size.
         */
        inline uintptr_t loadSize() const
        {
            return _loadSize;
        }

        /**
         * @brief Elf's dynamic section address in memory.
         */
        inline uintptr_t dynamic() const
        {
            return _dynamic;
        }

        /**
         * @brief Vector of Elf's dynamic sections.
         */
        inline std::vector<KT_ElfW(Dyn)> dynamics() const
        {
            return _dynamics;
        }

        /**
         * @brief Elf's dynamic string table address in memory.
         */
        inline uintptr_t stringTable() const
        {
            return _stringTable;
        }

        /**
         * @brief Elf's dynamic symbol table address in memory.
         */
        inline uintptr_t symbolTable() const
        {
            return _symbolTable;
        }

        /**
         * @brief Elf's dynamic string table size.
         */
        inline size_t stringTableSize() const
        {
            return _strsz;
        }

        /**
         * @brief Elf's symbol entry size.
         */
        inline size_t symbolEntrySize() const
        {
            return _syment;
        }

        /**
         * @brief Elf's dynamic hash table address in memory.
         */
        inline uintptr_t elfHashTable() const
        {
            return _elfHashTable;
        }

        /**
         * @brief Elf's dynamic GNU hash table address in memory.
         */
        inline uintptr_t gnuHashTable() const
        {
            return _gnuHashTable;
        }

        /**
         * @brief Finds a symbol from the dynamic symbol table by name.
         *
         * @param symbolName The name of the symbol to find.
         * @return The memory address of the symbol if found, otherwise zero.
         */
        uintptr_t findSymbol(const std::string &symbolName) const;

        /**
         * @brief Returns a map of symbols from the symbol table (SHT_SYMTAB) on disk.
         * @return A map where keys are symbol names and values are their corresponding memory addresses.
         */
        std::unordered_map<std::string, uintptr_t> dsymbols();

        /**
         * @brief Finds a symbol from the symbol table (SHT_SYMTAB) on disk by name.
         *
         * @param symbolName The name of the symbol to find.
         * @return The memory address of the symbol if found, otherwise zero.
         */
        uintptr_t findDebugSymbol(const std::string &symbolName);

        /**
         * @brief Elf's base memory map info.
         */
        KittyMemory::ProcMap baseSegment() const
        {
            return _baseSegment;
        }

        /**
         * @brief Returns all of Elf's memory maps info.
         */
        std::vector<KittyMemory::ProcMap> segments() const
        {
            return _segments;
        }

        /**
         * @brief Returns all of Elf's BSS memory maps.
         */
        std::vector<KittyMemory::ProcMap> bssSegments() const
        {
            return _bssSegments;
        }

        /**
         * @brief Returns the file path of the memory mapped Elf file.
         */
        inline std::string filePath() const
        {
            return _filepath;
        }

        /**
         * @brief Returns the real path of the memory mapped Elf file
         * (e.g, incase if it's inside a zip, it will return full path to zip entry).
         */
        inline std::string realPath() const
        {
            return _realpath;
        }

        /**
         * @brief Returns if the memory mapped Elf file was loaded from zip file.
         */
        inline bool isZipped() const
        {
            return _baseSegment.offset != 0;
        }

        /**
         * @brief Returns if the memory mapped Elf is native to android device.
         */
        inline bool isNative() const
        {
            int a = getProgramElf().header().e_machine, b = _ehdr.e_machine;
            return a != 0 && b != 0 && a == b;
        }

        /**
         * @brief Returns if the memory mapped Elf file is emulated to android device.
         */
        inline bool isEmulated() const
        {
            int a = getProgramElf().header().e_machine, b = _ehdr.e_machine;
            return a != 0 && b != 0 && a != b;
        }

        /**
         * @brief Finds the r_debug structure in the process.
         * @param out Pointer to store the r_debug structure.
         * @return True if the r_debug structure is found, false otherwise.
         */
        inline bool find_r_debug(r_debug *out) const
        {
            for (auto &it : _dynamics)
            {
                if (it.d_tag == DT_DEBUG && it.d_un.d_val)
                {
                    if (out)
                        memcpy(out, (void *)(it.d_un.d_val), sizeof(r_debug));

                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Finds a registered native JNI function in the process.
         * @param name The name of the native function.
         * @param signature The signature of the native function.
         * @return The registered native function info.
         */
        RegisterNativeFn findRegisterNativeFn(const std::string &name, const std::string &signature) const;

        /**
         * @brief Dumps the memory mapped ELF to disk.
         * @param destination The destination path for the dump.
         * @return True if the dump is successful, false otherwise.
         */
        bool dumpToDisk(const std::string &destination) const;

        /**
         * @brief Returns the program ELF.
         */
        static ElfScanner &getProgramElf();

        /**
         * @brief Fetches all memory mapped ELFs.
         * @param type (optional) The type of ELF file to find (e.g., Any, Native, Emulated).
         * @param filter (optional) The filter to apply when searching for ELF files (e.g., Any, System, App).
         * @return A vector of all memory mapped ELFs.
         */
        static std::vector<ElfScanner> getAllELFs(EScanElfType type = EScanElfType::Any,
                                                  EScanElfFilter filter = EScanElfFilter::Any);

        /**
         * @brief Searches for a memory mapped ELF file based on the given path, type, and filter.
         * @note If multiple ELFs found, it will prioritize ELFs with dynamic and return the latest mapped one with the
         * most segments. This function can extract full path to loaded zipped Elf files.
         *
         * @param path The path to the ELF file to find.
         * @param type (optional) The type of ELF file to find (e.g., Any, Native, Emulated).
         * @param filter (optional) The filter to apply when searching for ELF files. (e.g., Any, System, App).
         * @return An ElfScanner object representing the found ELF file, or an empty ElfScanner object if not found.
         */
        static ElfScanner findElf(const std::string &path,
                                  EScanElfType type = EScanElfType::Any,
                                  EScanElfFilter filter = EScanElfFilter::Any);

        /**
         * @brief Lookup dynamic symbol name in all loaded ELFs
         * @param symbolName The name of the symbol to lookup.
         * @param type (optional) The type of ELF file to find (e.g., Any, Native, Emulated).
         * @param filter (optional) The filter to apply when searching for ELF files. (e.g., Any, System, App).
         * @return A vector of pairs containing the symbol's absolute address and the ELF where the symbol was found.
         */
        static std::vector<std::pair<uintptr_t, ElfScanner>> findSymbolAll(const std::string &symbolName,
                                                                           EScanElfType type = EScanElfType::Any,
                                                                           EScanElfFilter filter = EScanElfFilter::Any);

        /**
         * @brief Constructs ElfScanner class with the given ELF base address.
         *
         * @param elfBase The base address of the ELF file in memory.
         * @param maps The vector of cached process memory maps (optional).
         */
        static ElfScanner createWithBase(uintptr_t elfBase,
                                         const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(elfBase, maps);
        }

        /**
         * @brief Constructs ElfScanner class with the given process memory map info.
         *
         * @param elfMap The base process memory map of the ELF file.
         * @param maps The vector of cached process memory maps (optional).
         */
        static ElfScanner createWithMap(const KittyMemory::ProcMap &elfMap,
                                        const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(elfMap.startAddress, maps);
        }

        /**
         * @brief Constructs ElfScanner class with the given soinfo.
         *
         * @param soinfo The soinfo of the ELF file.
         * @param maps The vector of cached process memory maps (optional).
         */
        static ElfScanner createWithSoInfo(const kitty_soinfo_t &soinfo,
                                           const std::vector<KittyMemory::ProcMap> &maps = KittyMemory::getAllMaps())
        {
            return ElfScanner(soinfo, maps);
        }
    };

    /**
     * @brief Structure to hold info of linker symbols
     */
    struct kitty_linker_syms_t
    {
        uintptr_t solist = 0;
        uintptr_t somain = 0;
        uintptr_t sonext = 0;
    };

    /**
     * @brief Structure to hold info of linker soinfo offsets
     */
    struct kitty_soinfo_offsets_t
    {
        uintptr_t base = 0;
        uintptr_t size = 0;
        uintptr_t phdr = 0;
        uintptr_t phnum = 0;
        uintptr_t dyn = 0;
        uintptr_t strtab = 0;
        uintptr_t symtab = 0;
        uintptr_t strsz = 0;
        uintptr_t bias = 0;
        uintptr_t next = 0;
    };

    /**
     * @brief Class for linker Elf.
     *
     * This class inherits from ElfScanner and provides methods for linker Elf.
     */
    class LinkerScanner : public ElfScanner
    {
    protected:
        kitty_linker_syms_t _linker_syms;
        kitty_soinfo_offsets_t _soinfo_offsets;
        bool _init;

        /**
         * @brief Initializes the linker scanner.
         * @return True if initialization is successful, false otherwise.
         */
        bool init();

    public:
        LinkerScanner() : ElfScanner(), _init(false)
        {
            memset(&_linker_syms, 0, sizeof(_linker_syms));
            memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        }

        /**
         * @brief Constructor for LinkerScanner with a linker base address.
         * @param linkerBase The base address of the linker.
         */
        LinkerScanner(uintptr_t linkerBase);

        /**
         * @brief Constructor for LinkerScanner with the linker ElfScanner object.
         * @param linkerElf Linker ElfScanner object.
         */
        LinkerScanner(const ElfScanner &linkerElf);

        /**
         * @brief Static method to get the LinkerScanner instance.
         */
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

        /**
         * @brief Converts the LinkerScanner object to an ElfScanner pointer.
         * @return The ElfScanner pointer.
         */
        inline ElfScanner *asELF() const
        {
            return (ElfScanner *)this;
        }

        /**
         * @brief Returns the linker symbols offsets.
         */
        inline kitty_linker_syms_t linker_offsets() const
        {
            return _linker_syms;
        }

        /**
         * @brief Returns the soinfo offsets.
         */
        inline kitty_soinfo_offsets_t soinfo_offsets() const
        {
            return _soinfo_offsets;
        }

        /**
         * @brief Returns the linker solist head address.
         */
        inline uintptr_t solist() const
        {
            if (!isValid() || !_linker_syms.solist)
                return 0;

            return *(uintptr_t *)(_linker_syms.solist);
        }

        /**
         * @brief Returns the linker somain address.
         */
        inline uintptr_t somain() const
        {
            if (!isValid() || !_linker_syms.somain)
                return 0;

            return *(uintptr_t *)(_linker_syms.somain);
        }

        /**
         * @brief Returns the linker solist tail address.
         */
        inline uintptr_t sonext() const
        {
            if (!isValid() || !_linker_syms.sonext)
                return 0;

            return *(uintptr_t *)(_linker_syms.sonext);
        }

        /**
         * @brief Returns the linker somain info.
         */
        inline kitty_soinfo_t somainInfo() const
        {
            if (!isValid() || !_linker_syms.somain)
                return {};

            return infoFromSoInfo_(somain(), KittyMemory::getAllMaps());
        }

        /**
         * @brief Returns the linker solist tail info.
         */
        inline kitty_soinfo_t sonextInfo() const
        {
            if (!isValid() || _linker_syms.sonext)
                return {};

            return infoFromSoInfo_(sonext(), KittyMemory::getAllMaps());
        }

        /**
         * @brief Returns all linker's soinfo.
         */
        std::vector<kitty_soinfo_t> allSoInfo() const;

        /**
         * @brief Finds a soinfo by name.
         * @param name The name of the soinfo.
         * @return The soinfo if found or empty object.
         */
        kitty_soinfo_t findSoInfo(const std::string &name) const;

    private:
        kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const;
    };

    enum KT_JNICallType
    {
        KT_JNICallTypeRegular = 1,
        KT_JNICallTypeCriticalNative = 2,
    };

    enum KT_NativeBridgeImplementationVersion
    {
        // first version, not used.
        KT_NB_DEFAULT_VERSION = 1,
        // The version which signal semantic is introduced.
        KT_NB_SIGNAL_VERSION = 2,
        // The version which namespace semantic is introduced.
        KT_NB_NAMESPACE_VERSION = 3,
        // The version with vendor namespaces
        KT_NB_VENDOR_NAMESPACE_VERSION = 4,
        // The version with runtime namespaces
        KT_NB_RUNTIME_NAMESPACE_VERSION = 5,
        // The version with pre-zygote-fork hook to support app-zygotes.
        KT_NB_PRE_ZYGOTE_FORK_VERSION = 6,
        // The version with critical_native support
        KT_NB_CRITICAL_NATIVE_SUPPORT_VERSION = 7,
        // The version with native bridge detection fallback for function pointers
        KT_NB_IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION = 8,
    };

    /**
     * @brief Structure to hold info of native bridge callbacks data.
     */
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
        void *(*createNamespace)(const char *name,
                                 const char *ld_library_path,
                                 const char *default_library_path,
                                 uint64_t type,
                                 const char *permitted_when_isolated_path,
                                 void *parent_ns);
        bool (*linkNamespaces)(void *from, void *to, const char *shared_libs_sonames);
        void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
        void *(*getVendorNamespace)();
        void *(*getExportedNamespace)(const char *name);
        void (*preZygoteFork)();
        void *(*getTrampolineWithJNICallType)(void *handle,
                                              const char *name,
                                              const char *shorty,
                                              uint32_t len,
                                              enum KT_JNICallType jni_call_type);
        void *(*getTrampolineForFunctionPointer)(const void *method,
                                                 const char *shorty,
                                                 uint32_t len,
                                                 enum KT_JNICallType jni_call_type);
        bool (*isNativeBridgeFunctionPointer)(const void *method);

        inline static size_t GetStructSize(int version)
        {
            switch (version)
            {
            case KT_NB_SIGNAL_VERSION:
                return sizeof(uintptr_t) * 8;
            case KT_NB_NAMESPACE_VERSION:
                return sizeof(uintptr_t) * 15;
            case KT_NB_VENDOR_NAMESPACE_VERSION:
                return sizeof(uintptr_t) * 16;
            case KT_NB_RUNTIME_NAMESPACE_VERSION:
                return sizeof(uintptr_t) * 17;
            case KT_NB_PRE_ZYGOTE_FORK_VERSION:
                return sizeof(uintptr_t) * 18;
            case KT_NB_CRITICAL_NATIVE_SUPPORT_VERSION:
                return sizeof(uintptr_t) * 19;
            case KT_NB_IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION:
                return sizeof(uintptr_t) * 21;
            }
            return 0;
        }
    };

    /**
     * @brief Class for scanning native bridge.
     */
    class NativeBridgeScanner
    {
    private:
        ElfScanner _nbElf, _nbImplElf, _sodlElf;
        uintptr_t _sodl;
        kitty_soinfo_offsets_t _soinfo_offsets;
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

        /**
         * @brief Static method to get the NativeBridgeScanner instance.
         */
        inline static NativeBridgeScanner &Get()
        {
            static NativeBridgeScanner nb{};
            ((void)nb.init());
            return nb;
        }

        /**
         * @brief Initializes the native bridge scanner.
         * @return True if initialization is successful, false otherwise.
         */
        bool init();

        /**
         * @brief Returns true if initialized, false otherwise.
         */
        inline bool isValid() const
        {
            return _init;
        }

        /**
         * @brief Returns the soinfo offsets.
         */
        inline kitty_soinfo_offsets_t soinfo_offsets() const
        {
            return _soinfo_offsets;
        }

        /**
         * @brief Getter for 'libnativebridge.so' Elf.
         */
        inline ElfScanner &nbElf()
        {
            return _nbElf;
        }

        /**
         * @brief Getter for the native bridge implementaion Elf (e.g, 'libhoudini.so' or 'libndk_translation.so').
         */
        inline ElfScanner &nbImplElf()
        {
            return _nbImplElf;
        }

        /**
         * @brief Getter for the emulated 'libdl.so' Elf.
         */
        inline ElfScanner &sodlElf()
        {
            return _sodlElf;
        }

        /**
         * @brief Check if the native bridge implementaion is Houdini.
         */
        inline bool isHoudini() const
        {
            return _isHoudini;
        }

        /**
         * @brief Returns the emulated libdl.so address.
         */
        inline uintptr_t sodl() const
        {
            return _sodl;
        }

        /**
         * @brief Returns the emulated libdl.so soinfo.
         */
        inline kitty_soinfo_t sodlInfo() const
        {
            if (!_init || !_sodl)
                return {};

            return infoFromSoInfo_(_sodl, KittyMemory::getAllMaps());
        }

        /**
         * @brief Returns all emulated soinfo.
         */
        std::vector<kitty_soinfo_t> allSoInfo() const;

        /**
         * @brief Finds a soinfo by name.
         * @param name The name of the soinfo.
         * @return The soinfo if found or empty object.
         */
        kitty_soinfo_t findSoInfo(const std::string &name) const;

        /**
         * @brief Returns native bridge callbacks data size.
         */
        inline size_t nbItfDataSize() const
        {
            return _nbItf_data_size;
        }

        /**
         * @brief Returns native bridge callbacks data.
         */
        inline nbItf_data_t nbItfData() const
        {
            return _nbItf_data;
        }

    private:
        kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const;
    };

    /**
     * @brief Class for native bridge dynamic linker funcions.
     */
    class NativeBridgeLinker
    {
    public:
        /// @brief native bride load library
        static void *dlopen(const std::string &path, int flags);
        /// @brief native bridge get trampoline
        static void *dlsym(void *handle, const std::string &sym_name);
        /// @brief native bridge unload library
        static int dlclose(void *handle);
        /// @brief native bridge dlerror
        static const char *dlerror();
        /// @brief native bridge dlladdr
        static bool dladdr(const void *addr, kitty_soinfo_t *info);
        /// @brief native bridge dl_iterate_phdr
        static void dl_iterate_phdr(const std::function<bool(const kitty_soinfo_t *info)> &callback);
    };

#endif // __ANDROID__

} // namespace KittyScanner
