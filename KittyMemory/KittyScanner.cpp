#include "KittyScanner.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include "KittyPtrValidator.hpp"

#ifdef __ANDROID__
#include <map>
#include <dlfcn.h>
#endif

#include "KittyUtils.hpp"

// refs
// https://github.com/learn-more/findpattern-bench

namespace KittyScanner
{

    bool compare(const char *data, const char *pattern, const char *mask)
    {
        for (; *mask; ++mask, ++data, ++pattern)
        {
            if (*mask == 'x' && *data != *pattern)
                return false;
        }
        return !*mask;
    }

    uintptr_t findInRange(const uintptr_t start, const uintptr_t end,
                          const char *pattern, const std::string &mask)
    {
        const size_t scan_size = mask.length();

        if (scan_size < 1 || ((start + scan_size) > end))
            return 0;

        const size_t length = end - start;

        for (size_t i = 0; i < length; ++i)
        {
            const uintptr_t current_end = start + i + scan_size;
            if (current_end > end)
                break;

            if (!compare(reinterpret_cast<const char *>(start + i), pattern, mask.c_str()))
                continue;

            return start + i;
        }
        return 0;
    }

    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end,
                                        const char *bytes, const std::string &mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !bytes || mask.empty())
            return list;

        uintptr_t curr_search_address = start;
        const size_t scan_size = mask.length();
        do
        {
            if (!list.empty()) curr_search_address = list.back() + scan_size;

            uintptr_t found = findInRange(curr_search_address, end, bytes, mask);
            if (!found) break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask)
    {
        if (start >= end || !bytes || mask.empty())
            return 0;

        return findInRange(start, end, bytes, mask);
    }

    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex)) return list;

        const size_t scan_size = mask.length();
        if ((hex.length() / 2) != scan_size) return list;

        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        list = findBytesAll(start, end, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask)
    {
        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex)) return 0;

        const size_t scan_size = mask.length();
        if ((hex.length() / 2) != scan_size) return 0;

        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        return findBytesFirst(start, end, pattern.data(), mask);
    }

    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string &pattern)
    {
        std::vector<uintptr_t> list;

        if (start >= end)
            return list;

        std::string mask;
        std::vector<char> bytes;

        const size_t pattren_len = pattern.length();
        for (std::size_t i = 0; i < pattren_len; i++)
        {
            if (pattern[i] == ' ') continue;

            if (pattern[i] == '?')
            {
                bytes.push_back(0);
                mask += '?';
            }
            else if (pattren_len > i + 1 && std::isxdigit(pattern[i]) && std::isxdigit(pattern[i + 1]))
            {
                bytes.push_back(std::stoi(pattern.substr(i++, 2), nullptr, 16));
                mask += 'x';
            }
        }

        if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
            return list;

        list = findBytesAll(start, end, bytes.data(), mask);
        return list;
    }

    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern)
    {
        if (start >= end)
            return 0;

        std::string mask;
        std::vector<char> bytes;

        const size_t pattren_len = pattern.length();
        for (std::size_t i = 0; i < pattren_len; i++)
        {
            if (pattern[i] == ' ') continue;

            if (pattern[i] == '?')
            {
                bytes.push_back(0);
                mask += '?';
            }
            else if (pattren_len > i + 1 && std::isxdigit(pattern[i]) && std::isxdigit(pattern[i + 1]))
            {
                bytes.push_back(std::stoi(pattern.substr(i++, 2), nullptr, 16));
                mask += 'x';
            }
        }

        if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
            return 0;

        return findBytesFirst(start, end, bytes.data(), mask);
    }

    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !data || size < 1)
            return list;

        std::string mask(size, 'x');

        list = findBytesAll(start, end, (const char *)data, mask);
        return list;
    }

    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        if (start >= end || !data || size < 1)
            return 0;

        std::string mask(size, 'x');

        return findBytesFirst(start, end, (const char *)data, mask);
    }

#ifdef __ANDROID__

// for old ndk
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

    /* ======================= ElfScanner ======================= */

    // refs https://gist.github.com/resilar/24bb92087aaec5649c9a2afc0b4350c8

    ElfScanner::ElfScanner(uintptr_t elfBase, const std::vector<KittyMemory::ProcMap> &maps)
    {
        _elfBase = 0;
        _ehdr = {};
        _phdr = 0;
        _loads = 0;
        _loadBias = 0;
        _loadSize = 0;
        _dynamic = 0;
        _stringTable = 0;
        _symbolTable = 0;
        _elfHashTable = 0;
        _gnuHashTable = 0;
        _strsz = 0;
        _syment = sizeof(KT_ElfW(Sym));
        _headerless = false;
        _dsymbols_init = false;

        if (!elfBase)
            return;

        // verify address
        auto elfBaseMap = KittyMemory::getAddressMap(maps, elfBase);
        if (!elfBaseMap.isValid() || !elfBaseMap.readable || elfBase != elfBaseMap.startAddress)
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF base address.", (void *)elfBase);
            return;
        }

        // verify ELF header
        if (!elfBaseMap.isValidELF())
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF.", (void *)elfBase);
            return;
        }

        _elfBase = elfBase;

        // read ELF header
        _ehdr = *(KT_ElfW(Ehdr) *)_elfBase;

        // check ELF bit
        if (_ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
        {
            KITTY_LOGD("ElfScanner: ELF class mismatch (%p).", (void *)_elfBase);
            return;
        }

        // check common header values
        if (!_ehdr.e_phoff || !_ehdr.e_phnum || !_ehdr.e_phentsize || !_ehdr.e_shnum || !_ehdr.e_shentsize)
        {
            KITTY_LOGD("ElfScanner: Invalid header values (%p).", (void *)_elfBase);
            return;
        }

        if (!KittyMemory::getAddressMap(maps, _elfBase + _ehdr.e_phoff).readable)
        {
            KITTY_LOGD("ElfScanner: Invalid phdr (%p + %p) = %p.", (void *)_elfBase, (void *)_ehdr.e_phoff, (void *)(_elfBase + _ehdr.e_phoff));
            return;
        }

        _phdr = _elfBase + _ehdr.e_phoff;

        // find load bias
        uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
        uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
        for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
        {
            if (!KittyMemory::getAddressMap(maps, _phdr + (i * _ehdr.e_phentsize)).readable)
                continue;

            KT_ElfW(Phdr) phdr_entry = {};
            memcpy(&phdr_entry, (const void *)(_phdr + (i * _ehdr.e_phentsize)), _ehdr.e_phentsize);
            _phdrs.push_back(phdr_entry);

            if (phdr_entry.p_type == PT_LOAD)
            {
                _loads++;

                load_vaddr = phdr_entry.p_vaddr;
                load_memsz = phdr_entry.p_memsz;
                load_filesz = phdr_entry.p_filesz;

                if (phdr_entry.p_vaddr < min_vaddr)
                    min_vaddr = phdr_entry.p_vaddr;

                if (phdr_entry.p_vaddr + phdr_entry.p_memsz > max_vaddr)
                    max_vaddr = phdr_entry.p_vaddr + phdr_entry.p_memsz;
            }
        }

        if (!_loads)
        {
            KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
            return;
        }

        if (!max_vaddr)
        {
            KITTY_LOGD("ElfScanner: failed to find load size for ELF (%p).", (void *)_elfBase);
            return;
        }

        min_vaddr = KT_PAGE_START(min_vaddr);
        max_vaddr = KT_PAGE_END(max_vaddr);

        _loadBias = _elfBase - min_vaddr;
        _loadSize = max_vaddr - min_vaddr;

        uintptr_t seg_start = load_vaddr + _loadBias;
        uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
        uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
        uintptr_t bss_start = 0, bss_end = 0;
        if (seg_mem_end > seg_file_end)
        {
            bss_start = seg_file_end;
            bss_end = seg_mem_end;
        }

        // read all dynamics
        for (auto &phdr : _phdrs)
        {
            if (phdr.p_type == PT_DYNAMIC)
            {
                if (phdr.p_vaddr == 0 || phdr.p_memsz == 0)
                    break;
                if (!KittyMemory::getAddressMap(maps, _loadBias + phdr.p_vaddr).readable)
                    break;
                if (!KittyMemory::getAddressMap(maps, (_loadBias + phdr.p_vaddr) + phdr.p_memsz - 1).readable)
                    break;

                _dynamic = _loadBias + phdr.p_vaddr;

                std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
                memcpy(&dyn_buff[0], (const void *)_dynamic, phdr.p_memsz);

                for (auto &dyn : dyn_buff)
                {
                    if (dyn.d_tag == DT_NULL)
                        break;

                    // set required dynamics for symbol lookup
                    switch (dyn.d_tag)
                    {
                        // mandatory
                    case DT_STRTAB:  // string table
                        _stringTable = dyn.d_un.d_ptr;
                        break;
                        // mandatory
                    case DT_SYMTAB:  // symbol table
                        _symbolTable = dyn.d_un.d_ptr;
                        break;
                    case DT_HASH:  // hash table
                        _elfHashTable = dyn.d_un.d_ptr;
                        break;
                    case DT_GNU_HASH:  // gnu hash table
                        _gnuHashTable = dyn.d_un.d_ptr;
                        break;
                        // mandatory
                    case DT_STRSZ:  // string table size
                        _strsz = dyn.d_un.d_val;
                        break;
                        // mandatory
                    case DT_SYMENT:  // symbol entry size
                        _syment = dyn.d_un.d_val;
                        break;
                    default:
                        break;
                    }

                    _dynamics.push_back(dyn);
                }
                break;
            }
        }

        auto fix_table_address = [&](uintptr_t &table_addr)
        {
            if (table_addr && table_addr < _loadBias)
                table_addr += _loadBias;

            if (!KittyMemory::getAddressMap(maps, table_addr).readable)
                table_addr = 0;
        };

        fix_table_address(_stringTable);
        fix_table_address(_symbolTable);
        fix_table_address(_elfHashTable);
        fix_table_address(_gnuHashTable);

        if (_loadSize)
        {
            for (auto &it : maps)
            {
                if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
                {
                    if (it.startAddress == _elfBase)
                    {
                        _base_segment = it;
                    }
                    _segments.push_back(it);
                }

                if (it.endAddress >= (_elfBase + _loadSize))
                    break;
            }

            if (!_segments.empty())
            {
                _filepath = _base_segment.pathname;
                _realpath = _base_segment.pathname;
                if (!_base_segment.pathname.empty() && _base_segment.offset != 0)
                {
                    std::string inZipPath = KittyUtils::Zip::GetFileInfoByDataOffset(_base_segment.pathname, _base_segment.offset).fileName;
                    if (!inZipPath.empty())
                    {
                        _realpath += '!';
                        _realpath += inZipPath;
                    }
                }

                for (const auto &it : _segments)
                {
                    if ((bss_start && bss_end && it.startAddress >= bss_start && it.endAddress <= bss_end) || it.pathname == "[anon:.bss]")
                    {
                        _bss_segments.push_back(it);
                    }
                }
            }
        }
    }

    ElfScanner::ElfScanner(const soinfo_info_t &soinfo, const std::vector<KittyMemory::ProcMap> &maps)
    {
        _elfBase = 0;
        _ehdr = {};
        _phdr = 0;
        _loads = 0;
        _loadBias = 0;
        _loadSize = 0;
        _dynamic = 0;
        _stringTable = 0;
        _symbolTable = 0;
        _elfHashTable = 0;
        _gnuHashTable = 0;
        _strsz = 0;
        _syment = 0;
        _headerless = false;
        _dsymbols_init = false;

        _elfBase = soinfo.base;
        _phdr = soinfo.phdr;
        _loadBias = soinfo.bias;
        _loadSize = soinfo.size;
        _dynamic = soinfo.dyn;
        _stringTable = soinfo.strtab;
        _symbolTable = soinfo.symtab;
        _strsz = soinfo.strsz;
        _syment = sizeof(KT_ElfW(Sym));
        _filepath = soinfo.path;
        _realpath = soinfo.realpath;

        bool isLinker = KittyUtils::String::EndsWith(soinfo.path, "/linker") || KittyUtils::String::EndsWith(soinfo.path, "/linker64");
        if ((!isLinker && (_elfBase == 0 || _loadSize == 0)) || _loadBias == 0 || _phdr == 0 || _dynamic == 0 || _stringTable == 0 || _symbolTable == 0)
        {
            KITTY_LOGD("ElfScanner: Invalid soinfo!");
            KITTY_LOGD("ElfScanner: elfBase: %p | bias: %p | phdr: %p | dyn: %p | strtab=%p | symtab=%p | strsz=%p | syment=%p",
                       (void *)_elfBase, (void *)_loadBias, (void *)_phdr, (void *)_dynamic, (void *)_stringTable, (void *)_symbolTable, (void *)_strsz, (void *)_syment);
            return;
        }

        // fix for linker
        if (_elfBase == 0)
        {
            _elfBase = KittyMemory::getAddressMap(maps, soinfo.bias).startAddress;
        }

        uintptr_t bss_start = 0, bss_end = 0;

        do
        {
            // verify address
            auto elfBaseMap = KittyMemory::getAddressMap(maps, _elfBase);
            if (!elfBaseMap.isValid() || !elfBaseMap.readable || _elfBase != elfBaseMap.startAddress)
            {
                KITTY_LOGD("ElfScanner: (%p) is not a valid ELF base address.", (void *)_elfBase);
                break;
            }

            // verify ELF header
            if (!elfBaseMap.isValidELF())
            {
                // maybe protected
                _headerless = true;
                KITTY_LOGD("ElfScanner: failed to read ELF header for soinfo(%p).", (void *)_elfBase);
                break;
            }

            // check ELF bit
            if (_ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
            {
                KITTY_LOGD("ElfScanner: ELF class mismatch (%p).", (void *)_elfBase);
                break;
            }

            // check common header values
            if (!_ehdr.e_phoff || _ehdr.e_phnum || !_ehdr.e_phentsize || !_ehdr.e_shnum || !_ehdr.e_shentsize)
            {
                KITTY_LOGD("ElfScanner: Invalid header values (%p).", (void *)_elfBase);
                break;
            }

            if (!KittyMemory::getAddressMap(maps, _phdr).readable)
            {
                KITTY_LOGD("ElfScanner: Invalid phdr (%p + %p) = %p.", (void *)_elfBase, (void *)_ehdr.e_phoff, (void *)_phdr);
                break;
            }

            uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
            uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
            for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
            {
                if (!KittyMemory::getAddressMap(maps, _phdr + (i * _ehdr.e_phentsize)).readable)
                    continue;

                KT_ElfW(Phdr) phdr_entry = {};
                memcpy(&phdr_entry, (const void *)(_phdr + (i * _ehdr.e_phentsize)), _ehdr.e_phentsize);
                _phdrs.push_back(phdr_entry);

                if (phdr_entry.p_type == PT_LOAD)
                {
                    _loads++;

                    load_vaddr = phdr_entry.p_vaddr;
                    load_memsz = phdr_entry.p_memsz;
                    load_filesz = phdr_entry.p_filesz;

                    if (phdr_entry.p_vaddr < min_vaddr)
                        min_vaddr = phdr_entry.p_vaddr;

                    if (phdr_entry.p_vaddr + phdr_entry.p_memsz > max_vaddr)
                        max_vaddr = phdr_entry.p_vaddr + phdr_entry.p_memsz;
                }
            }

            if (!_loads)
            {
                KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
                break;
            }

            if (!max_vaddr)
            {
                KITTY_LOGD("ElfScanner: failed to find load size for ELF (%p).", (void *)_elfBase);
                break;
            }

            min_vaddr = KT_PAGE_START(min_vaddr);
            max_vaddr = KT_PAGE_END(max_vaddr);

            // fix for linker
            if (_loadSize == 0)
            {
                _loadSize = max_vaddr - min_vaddr;
            }

            uintptr_t seg_start = load_vaddr + _loadBias;
            uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
            uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
            if (seg_mem_end > seg_file_end)
            {
                bss_start = seg_file_end;
                bss_end = seg_mem_end;
            }

            // read all dynamics
            for (auto &phdr : _phdrs)
            {
                if (phdr.p_type == PT_DYNAMIC)
                {
                    if (_dynamic == 0 || phdr.p_memsz == 0)
                        break;
                    if (!KittyMemory::getAddressMap(maps, _dynamic).readable)
                        break;
                    if (!KittyMemory::getAddressMap(maps, _dynamic + phdr.p_memsz - 1).readable)
                        break;

                    std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
                    memcpy(&dyn_buff[0], (const void *)_dynamic, phdr.p_memsz);

                    for (auto &dyn : dyn_buff)
                    {
                        if (dyn.d_tag == DT_NULL)
                            break;

                        switch (dyn.d_tag)
                        {
                        case DT_STRSZ:
                            if (_strsz == 0)
                            {
                                _strsz = dyn.d_un.d_val;
                            }
                            break;
                        case DT_SYMENT:
                            _syment = dyn.d_un.d_val;
                            break;
                        case DT_HASH:  // hash table
                            _elfHashTable = dyn.d_un.d_ptr;
                            break;
                        case DT_GNU_HASH:  // gnu hash table
                            _gnuHashTable = dyn.d_un.d_ptr;
                            break;
                        default:
                            break;
                        }

                        _dynamics.push_back(dyn);
                    }
                    break;
                }
            }

            auto fix_table_address = [&](uintptr_t &table_addr)
            {
                if (table_addr && table_addr < _loadBias)
                    table_addr += _loadBias;

                if (!KittyMemory::getAddressMap(maps, table_addr).readable)
                    table_addr = 0;
            };

            fix_table_address(_elfHashTable);
            fix_table_address(_gnuHashTable);

        } while (false);

        if (_loadSize)
        {
            for (auto &it : maps)
            {
                if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
                {
                    if (it.startAddress == _elfBase)
                    {
                        _base_segment = it;
                    }
                    _segments.push_back(it);
                }

                if (it.endAddress >= (_elfBase + _loadSize))
                    break;
            }

            if (!_segments.empty())
            {
                for (const auto &it : _segments)
                {
                    if ((bss_start && bss_end && it.startAddress >= bss_start && it.endAddress <= bss_end) || it.pathname == "[anon:.bss]")
                    {
                        _bss_segments.push_back(it);
                    }
                }
            }
        }
    }

    uintptr_t ElfScanner::findSymbol(const std::string &symbolName) const
    {
        if (_loadBias && _stringTable && _symbolTable && _strsz && _syment)
        {
            auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t
            {
                return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
            };

            // try gnu hash first
            if (_gnuHashTable)
            {
                const auto *sym = KittyUtils::Elf::GnuHash::LookupByName(_gnuHashTable, _symbolTable, _stringTable, _syment, _strsz, symbolName.c_str());
                if (sym && sym->st_value)
                {
                    return get_sym_address(sym);
                }
            }

            if (_elfHashTable)
            {
                const auto *sym = KittyUtils::Elf::ElfHash::LookupByName(_elfHashTable, _symbolTable, _stringTable, _syment, _strsz, symbolName.c_str());
                if (sym && sym->st_value)
                {
                    return get_sym_address(sym);
                }
            }
        }

        return 0;
    }

    std::unordered_map<std::string, uintptr_t> ElfScanner::dsymbols()
    {
        if (!_dsymbols_init && _loadBias && !_filepath.empty())
        {
            _dsymbols_init = true;

            auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t
            {
                return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
            };

            KittyUtils::Zip::ZipFileMMap mmap_info = {nullptr, 0};
            if (isZipped())
            {
                mmap_info = KittyUtils::Zip::MMapFileByDataOffset(_filepath, _base_segment.offset);
            }
            else
            {
                errno = 0;
                int fd = open(_filepath.c_str(), O_RDONLY);
                if (fd < 0)
                {
                    KITTY_LOGD("Failed to open file <%s> err(%d)", _filepath.c_str(), errno);
                    return _dsymbolsMap;
                }

                struct stat flstats;
                memset(&flstats, 0, sizeof(struct stat));
                int fstat_ret = fstat(fd, &flstats);
                size_t elfSize = flstats.st_size;
                if (fstat_ret == -1 || elfSize <= 0)
                {
                    close(fd);
                    KITTY_LOGD("stat failed for <%s>", _filepath.c_str());
                    return _dsymbolsMap;
                }
                mmap_info.data = mmap(nullptr, elfSize, PROT_READ, MAP_PRIVATE, fd, 0);
                mmap_info.size = elfSize;
                close(fd);
            }

            if (mmap_info.size == 0 || !mmap_info.data || mmap_info.data == ((void *)-1))
            {
                KITTY_LOGD("Failed to mmap <%s>", realPath().c_str());
                return _dsymbolsMap;
            }

            auto cleanup = [&]
            { munmap(mmap_info.data, mmap_info.size); };

            KT_ElfW(Ehdr) *ehdr = static_cast<KT_ElfW(Ehdr) *>(mmap_info.data);

            if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0)
            {
                KITTY_LOGD("<%s> is not a valid ELF", realPath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            if (ehdr->e_phoff == 0 || ehdr->e_phentsize == 0 || ehdr->e_phnum == 0 || ehdr->e_phoff + ehdr->e_phnum * sizeof(KT_ElfW(Phdr)) > mmap_info.size)
            {
                KITTY_LOGD("Invalid program header table in <%s>", filePath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            if (ehdr->e_shoff == 0 || ehdr->e_shentsize == 0 || ehdr->e_shnum == 0 || ehdr->e_shoff + ehdr->e_shnum * sizeof(KT_ElfW(Shdr)) > mmap_info.size)
            {
                KITTY_LOGD("Invalid section header table in <%s>", filePath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            const KT_ElfW(Shdr) *shdr = reinterpret_cast<KT_ElfW(Shdr) *>(static_cast<char *>(mmap_info.data) + ehdr->e_shoff);
            const KT_ElfW(Shdr) *shstrtab_shdr = shdr + ehdr->e_shstrndx;
            const char *sectionstr = reinterpret_cast<char *>(static_cast<char *>(mmap_info.data) + shstrtab_shdr->sh_offset);
            for (uint16_t i = 0; i < ehdr->e_shnum; ++i)
            {
                if (shdr[i].sh_type != SHT_SYMTAB)
                    continue;

                std::string section_name = std::string(reinterpret_cast<const char *>(sectionstr + shdr[i].sh_name));
                if (section_name.compare(".symtab") != 0)
                    continue;

                if ((shdr[i].sh_offset + shdr[i].sh_size) > mmap_info.size || shdr[i].sh_link >= ehdr->e_shnum ||
                    (shdr[shdr[i].sh_link].sh_offset + shdr[shdr[i].sh_link].sh_size) > mmap_info.size)
                    continue;

                const KT_ElfW(Sym) *symtab = reinterpret_cast<KT_ElfW(Sym) *>(static_cast<char *>(mmap_info.data) + shdr[i].sh_offset);
                const size_t symCount = shdr[i].sh_size / shdr[i].sh_entsize;
                const KT_ElfW(Shdr) *strtabShdr = &shdr[shdr[i].sh_link];
                const char *strtab = reinterpret_cast<char *>(static_cast<char *>(mmap_info.data) + strtabShdr->sh_offset);

                for (size_t j = 0; j < symCount; ++j)
                {
                    const KT_ElfW(Sym) *curr_sym = &symtab[j];
                    if (!curr_sym || curr_sym->st_name >= strtabShdr->sh_size)
                        continue;

                    if (intptr_t(curr_sym->st_value) <= 0 || intptr_t(curr_sym->st_size) <= 0)
                        continue;

                    if (KT_ELF_ST_TYPE(curr_sym->st_info) != STT_OBJECT && KT_ELF_ST_TYPE(curr_sym->st_info) != STT_FUNC)
                        continue;

                    std::string sym_str = std::string(reinterpret_cast<const char *>(strtab + curr_sym->st_name));
                    if (!sym_str.empty() && sym_str.data())
                        _dsymbolsMap[sym_str] = get_sym_address(curr_sym);
                }
            }
            cleanup();
        }
        return _dsymbolsMap;
    }

    uintptr_t ElfScanner::findDebugSymbol(const std::string &symbolName)
    {
        const auto &syms = dsymbols();
        auto it = syms.find(symbolName);
        return it != syms.end() ? it->second : 0;
    }

    RegisterNativeFn ElfScanner::findRegisterNativeFn(const std::string &name) const
    {
        uintptr_t string_loc = 0, string_xref = 0, fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || !isValid())
            return fn;

        for (auto &it : segments())
        {
            if (it.is_ro || it.is_rx)
            {
                string_loc = KittyScanner::findDataFirst(it.startAddress, it.endAddress, name.data(), name.length());
                if (string_loc) break;
            }
        }

        if (!string_loc)
        {
            KITTY_LOGD("findRegisterNativeFn: Couldn't find string (%s) in selected maps", name.c_str());
            return fn;
        }

        KITTY_LOGD("findRegisterNativeFn: String (%s) at %p", name.c_str(), (void *)string_loc);

        for (auto &it : segments())
        {
            if (it.is_rw)
            {
                string_xref = KittyScanner::findDataFirst(it.startAddress, it.endAddress, &string_loc, sizeof(uintptr_t));
                if (!string_xref) continue;

                KITTY_LOGD("findRegisterNativeFn: String at (%p) referenced at %p", (void *)string_loc, (void *)string_xref);

                fn_loc = string_xref;
                break;
            }
        }

        if (!fn_loc) return fn;

        memcpy(&fn, (void *)fn_loc, sizeof(RegisterNativeFn));
        return fn;
    }

    ElfScanner ElfScanner::findElf(const std::string &path)
    {
        ElfScanner ret{};

        if (path.empty())
            return ret;

        std::vector<ElfScanner> elfs;
        std::vector<ElfScanner> dyn_elfs;

        const auto allElfs = ElfScanner::GetAllELFs();
        for (const auto &it : allElfs)
        {
            if (it.isValid() && KittyUtils::String::EndsWith(it.realPath(), path))
            {
                if (it.dynamic() && it.dynamics().size() > 0)
                    dyn_elfs.push_back(it);
                else
                    elfs.push_back(it);
            }
        }

        if (elfs.empty() && dyn_elfs.empty())
            return ret;

        if (dyn_elfs.size() > 0)
        {
            if (dyn_elfs.size() == 1)
                return dyn_elfs[0];

            int nMostSegments = 0;
            for (auto &it : dyn_elfs)
            {
                int numSegments = it.segments().size();
                if (numSegments > nMostSegments)
                {
                    ret = it;
                    nMostSegments = numSegments;
                }
            }
        }
        else if (elfs.size() > 0)
        {
            if (elfs.size() == 1)
                return elfs[0];

            int nMostSegments = 0;
            for (auto &it : elfs)
            {
                int numSegments = it.segments().size();
                if (numSegments > nMostSegments)
                {
                    ret = it;
                    nMostSegments = numSegments;
                }
            }
        }

        return ret;
    }

    std::vector<ElfScanner> ElfScanner::GetAllELFs()
    {
        std::vector<ElfScanner> elfs;

        auto maps = KittyMemory::getAllMaps();
        if (maps.empty())
        {
            KITTY_LOGD("GetAllELFs: Failed to get process maps.");
            return elfs;
        }

        uintptr_t lastElfEndAddr = 0;

        for (auto &it : maps)
        {
            if (!it.isValid() || it.startAddress < lastElfEndAddr || !it.readable || it.pathname == "cfi shadow" || !it.isValidELF())
                continue;

            auto elf = ElfScanner(it.startAddress, maps);
            if (elf.isValid())
            {
                lastElfEndAddr = elf.end();
                elfs.push_back(elf);
            }
        }

        return elfs;
    }

    std::vector<ElfScanner> ElfScanner::GetAppELFs()
    {
        std::vector<ElfScanner> elfs;

        auto allMaps = KittyMemory::getAllMaps();
        auto maps = KittyMemory::getMapsContain("/data/app/");
        if (maps.empty())
        {
            KITTY_LOGD("GetAppELFs: Failed to get process maps.");
            return elfs;
        }

        uintptr_t lastElfEndAddr = 0;

        for (auto &it : maps)
        {
            if (!it.isValid() || it.startAddress < lastElfEndAddr || !it.readable || it.pathname == "cfi shadow" || !it.isValidELF())
                continue;

            auto elf = ElfScanner(it.startAddress, allMaps);
            if (elf.isValid())
            {
                lastElfEndAddr = elf.end();
                elfs.push_back(elf);
            }
        }

        return elfs;
    }

    std::vector<std::pair<uintptr_t, ElfScanner>> ElfScanner::findSymbolAll(const std::string &symbolName)
    {
        std::vector<std::pair<uintptr_t, ElfScanner>> ret{};

        auto elfs = GetAllELFs();
        for (auto &it : elfs)
        {
            uintptr_t sym = it.findSymbol(symbolName);
            if (sym != 0)
            {
                ret.emplace_back(sym, it);
            }
        }

        return ret;
    }

    LinkerScanner::LinkerScanner(uintptr_t linkerBase) : ElfScanner(linkerBase)
    {
        memset(&_linker_syms, 0, sizeof(_linker_syms));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        _init = false;

        if (!isValid()) return;

        init();
    }

    LinkerScanner::LinkerScanner(const ElfScanner &linkerElf) : ElfScanner(linkerElf)
    {
        memset(&_linker_syms, 0, sizeof(_linker_syms));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        _init = false;

        if (!isValid()) return;

        init();
    }

    bool LinkerScanner::init()
    {
        if (_init) return true;
        if (!isValid()) return false;

        for (const auto &sym : dsymbols())
        {
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6solist"))
            {
                _linker_syms.solist = sym.second;
                continue;
            }
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6somain"))
            {
                _linker_syms.somain = sym.second;
                continue;
            }
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6sonext"))
            {
                _linker_syms.sonext = sym.second;
                continue;
            }
            if (_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext)
                break;
        }

        if (!(_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext))
        {
            return false;
        }

        KITTY_LOGD("solist(%zx) | somain(%zx) | sonext(%zx)", solist(), somain(), sonext());

        auto maps = KittyMemory::getAllMaps();
        KittyPtrValidator kPtrValidator(getpid(), true);

        uintptr_t solist_ptr = solist();
        std::vector<char> solist_buf(KT_SOINFO_BUFFER_SZ, 0);
        for (size_t i = 0; i < solist_buf.size(); i += sizeof(uintptr_t))
        {
            if (kPtrValidator.isPtrReadable(solist_ptr + i))
            {
                memcpy((void *)(solist_buf.data() + i), (const void *)(solist_ptr + i), sizeof(uintptr_t));
            }
        }

        std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
        uintptr_t somain_ptr = (somain() ? somain() : sonext());
        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            if (kPtrValidator.isPtrReadable(somain_ptr + i))
            {
                memcpy((void *)(si_buf.data() + i), (const void *)(somain_ptr + i), sizeof(uintptr_t));
            }
        }

        ElfScanner si_elf{};
        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            si_elf = ElfScanner(*(uintptr_t *)&si_buf[i], maps);
            if (si_elf.isValid() && si_elf.dynamics().size())
            {
                _soinfo_offsets.base = i;
                break;
            }
        }

        KITTY_LOGD("soinfo_base(%zx)", _soinfo_offsets.base);

        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t value = *(uintptr_t *)&si_buf[i];

            if (value == si_elf.phdr())
                _soinfo_offsets.phdr = i;
            if (value == si_elf.programHeaders().size())
                _soinfo_offsets.phnum = i;
            else if (value == si_elf.loadSize())
                _soinfo_offsets.size = i;
            else if (value == si_elf.dynamic())
                _soinfo_offsets.dyn = i;
            else if (value == si_elf.stringTable())
                _soinfo_offsets.strtab = i;
            else if (value == si_elf.symbolTable())
                _soinfo_offsets.symtab = i;
            else if (value == si_elf.loadBias() && i != _soinfo_offsets.base)
                _soinfo_offsets.bias = i;
            else if (value == si_elf.stringTableSize())
                _soinfo_offsets.strsz = i;
        }

        KITTY_LOGD("soinfo_bias(%zx) | soinfo_size(%zx)", _soinfo_offsets.base, _soinfo_offsets.size);
        KITTY_LOGD("soinfo_phdr(%zx, %zx) | soinfo_dyn(%zx)", _soinfo_offsets.phdr, _soinfo_offsets.phnum, _soinfo_offsets.dyn);
        KITTY_LOGD("soinfo_strtab(%zx, %zx) | soinfo_symtab(%zx)", _soinfo_offsets.strtab, _soinfo_offsets.strsz, _soinfo_offsets.symtab);

        if (!(_soinfo_offsets.size && _soinfo_offsets.bias &&
              _soinfo_offsets.dyn && _soinfo_offsets.symtab &&
              _soinfo_offsets.strtab && _soinfo_offsets.strsz))
        {
            return false;
        }

        for (size_t i = 0; i < solist_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t value = *(uintptr_t *)&solist_buf[i];

            if (!kPtrValidator.isPtrReadable(value + _soinfo_offsets.base))
                continue;

            auto tmp_elf = ElfScanner(*(uintptr_t *)(value + _soinfo_offsets.base), maps);
            if (tmp_elf.isValid())
            {
                if (!kPtrValidator.isPtrReadable(value + _soinfo_offsets.size))
                    continue;

                if (tmp_elf.loadSize() == *(uintptr_t *)(value + _soinfo_offsets.size))
                {
                    _soinfo_offsets.next = i;
                    break;
                }
            }
        }

        KITTY_LOGD("soinfo_sonext(%zx)", _soinfo_offsets.next);

        _init = _soinfo_offsets.next != 0;
        return _init;
    }

    std::vector<soinfo_info_t> LinkerScanner::GetSoList() const
    {
        std::vector<soinfo_info_t> infos{};

        if (!isValid() || !_init) return infos;

        auto maps = KittyMemory::getAllMaps();
        uintptr_t si = solist();
        while (si && KittyMemory::getAddressMap(maps, si).readable)
        {
            soinfo_info_t info = GetInfoFromSoInfo_(si, maps);
            if (!info.bias) break;

            infos.push_back(info);

            si = *(uintptr_t *)(si + _soinfo_offsets.next);
        }
        return infos;
    }

    soinfo_info_t LinkerScanner::GetInfoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const
    {
        soinfo_info_t info{};

        if (!isValid() || !_init) return info;

        auto si_map = KittyMemory::getAddressMap(maps, *(uintptr_t *)(si + _soinfo_offsets.bias));
        if (si_map.isValid())
        {
            info.base = *(uintptr_t *)(si + _soinfo_offsets.base);
            info.size = *(uintptr_t *)(si + _soinfo_offsets.size);
            info.phdr = *(uintptr_t *)(si + _soinfo_offsets.phdr);
            info.phnum = *(uintptr_t *)(si + _soinfo_offsets.phnum);
            info.dyn = *(uintptr_t *)(si + _soinfo_offsets.dyn);
            info.strtab = *(uintptr_t *)(si + _soinfo_offsets.strtab);
            info.symtab = *(uintptr_t *)(si + _soinfo_offsets.symtab);
            info.strsz = *(uintptr_t *)(si + _soinfo_offsets.strsz);
            info.bias = *(uintptr_t *)(si + _soinfo_offsets.bias);
            info.next = *(uintptr_t *)(si + _soinfo_offsets.next);
            info.path = si_map.pathname;
            info.realpath = si_map.pathname;
            if (si_map.offset != 0)
            {
                std::string inZipPath = KittyUtils::Zip::GetFileInfoByDataOffset(si_map.pathname, si_map.offset).fileName;
                if (!inZipPath.empty())
                {
                    info.realpath += '!';
                    info.realpath += inZipPath;
                }
            }
        }

        return info;
    }

#endif  // __ANDROID__

}  // namespace KittyScanner